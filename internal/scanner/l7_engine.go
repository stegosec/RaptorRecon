// Package scanner — Port-Triggered L7 Execution Engine
//
// Refactorización: Port-Triggered Execution con doble validación Auto vs Manual.
//
// Reglas de ejecución:
//  1. PORT-TRIGGERED (ambos modos): tmpl.Port DEBE coincidir con el openPort detectado.
//     Nunca se disparan payloads a puertos cerrados o irrelevantes.
//  2. MODO AUTÓNOMO (--auto o IsAutoMode=true): Si pasa Regla 1, el template se ejecuta.
//  3. MODO MANUAL (TUI/CLI override): Doble validación — Regla 1 + template en AllowedL7IDs.
package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/raptor-recon/raptor/internal/proxy"
	"github.com/raptor-recon/raptor/internal/rules"
)

// ──────────────────────────────────────────────
// L7ExecutionMode — Política de ejecución
// ──────────────────────────────────────────────

// L7ExecutionMode controla si el motor ejecuta TODOS los templates (Auto)
// o solo los explícitamente autorizados por el usuario (Manual/TUI).
type L7ExecutionMode int

const (
	// L7ModeAuto: Modo autónomo — todos los templates se ejecutan si coincide el puerto.
	// Activado por --auto o cuando AllowedL7IDs está vacío.
	L7ModeAuto L7ExecutionMode = iota

	// L7ModeManual: Modo manual/TUI — solo los IDs en AllowedL7IDs se disparan.
	// Doble validación: puerto coincide Y template está en la lista blanca.
	L7ModeManual
)

// ──────────────────────────────────────────────
// PivotContext — Propagación de contexto de pivot a findings L7
// ──────────────────────────────────────────────

// PivotContext propaga el contexto de pivot a los findings L7 generados durante
// un sub-escaneo a través de un proxy. Valor cero {IsPivot: false} produce el
// comportamiento original de Dispatch() — backward-compatible.
type PivotContext struct {
	IsPivot   bool   // true si el L7 se ejecuta sobre un target de pivot
	ProxyHost string // host del proxy usado como túnel
	ProxyPort int    // puerto del proxy
	ProxyType string // "http-connect" | "socks5"
}

// ──────────────────────────────────────────────
// L7Dispatcher — Orquestador Port-Triggered
// ──────────────────────────────────────────────

// L7Dispatcher encapsula la lógica de despacho de templates L7 con
// doble validación: port-match (Regla 1) + autorización de modo (Reglas 2 y 3).
// Es thread-safe: su estado es de solo lectura tras la construcción.
type L7Dispatcher struct {
	// templates es el mapa de templates indexado por puerto para O(1) lookup.
	templates map[int][]rules.L7Template

	// mode determina la política de autorización.
	mode L7ExecutionMode

	// allowedIDs es el set de IDs autorizados en Modo Manual (lookup O(1)).
	// En Modo Auto este mapa está vacío y se ignora.
	allowedIDs map[string]struct{}
}

// NewL7Dispatcher construye un dispatcher configurado con la política correcta.
//
//   - templates: mapa de L7Templates indexado por puerto (de scanner.Config.L7Templates)
//   - isAutoMode: true si --auto está activo → L7ModeAuto
//   - allowedIDs: IDs de templates seleccionados en la TUI (Modo Manual).
//     Si está vacío, se usa L7ModeAuto como fallback seguro para no bloquear el escaneo.
func NewL7Dispatcher(templates map[int][]rules.L7Template, isAutoMode bool, allowedIDs []string) *L7Dispatcher {
	d := &L7Dispatcher{
		templates:  templates,
		allowedIDs: make(map[string]struct{}, len(allowedIDs)),
	}

	for _, id := range allowedIDs {
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			d.allowedIDs[trimmed] = struct{}{}
		}
	}

	// Si isAutoMode=true O no hay IDs explícitos → L7ModeAuto (todos autorizados).
	// Si isAutoMode=false Y hay IDs → L7ModeManual (solo los IDs de la lista blanca).
	if isAutoMode || len(d.allowedIDs) == 0 {
		d.mode = L7ModeAuto
	} else {
		d.mode = L7ModeManual
	}

	return d
}

// IsAuthorized aplica la doble validación Port-Triggered antes de cualquier conexión:
//
//  1. (Siempre) tmpl.Port == openPort — nunca disparamos a puertos cerrados.
//  2. (Siempre) tmpl.Protocol == openProtocol si está definido.
//  3. (Solo L7ModeManual) tmpl.ID está en la lista blanca allowedIDs del usuario.
func (d *L7Dispatcher) IsAuthorized(tmpl rules.L7Template, openPort int, openProtocol string) bool {
	// Regla 1: Port-Triggered — El puerto del template DEBE ser exactamente el puerto abierto.
	if tmpl.Port != openPort {
		return false
	}

	// Regla 1b: Protocolo — Si el template especifica protocolo, debe coincidir.
	if tmpl.Protocol != "" && tmpl.Protocol != openProtocol {
		return false
	}

	// Regla 2/3: En Modo Manual, además debe estar en la lista blanca del usuario.
	if d.mode == L7ModeManual {
		_, authorized := d.allowedIDs[tmpl.ID]
		return authorized
	}

	// Modo Auto: Si pasó la validación de puerto/protocolo, está autorizado.
	return true
}

// Dispatch ejecuta todos los templates autorizados para el par (host, openPort, openProtocol).
// Retorna todos los findings consolidados de los templates que produjeron un match.
//
// Thread-safe: cada goroutine de enrichment llama Dispatch de forma independiente.
func (d *L7Dispatcher) Dispatch(host string, openPort int, openProtocol string, timeout time.Duration, dialer proxy.ContextDialer) []rules.Finding {
	if d.templates == nil {
		return nil
	}

	// Lookup O(1) por puerto — solo templates apuntando exactamente a este puerto.
	candidates, ok := d.templates[openPort]
	if !ok || len(candidates) == 0 {
		return nil
	}

	var findings []rules.Finding
	for _, tmpl := range candidates {
		// Doble validación antes de cualquier intento de conexión (cero overhead si no autorizado).
		if !d.IsAuthorized(tmpl, openPort, openProtocol) {
			continue
		}
		findings = append(findings, ExecuteL7Template(host, tmpl, timeout, dialer)...)
	}
	return findings
}

// ──────────────────────────────────────────────
// DispatchWithContext ejecuta templates L7 exactamente como Dispatch(), pero además
// inyecta el contexto de pivot en el campo Context de cada finding generado.
//
// Usar cuando se ejecutan templates sobre targets de pivot para que los reportes
// puedan distinguir findings directos de findings obtenidos vía proxy.
//
// Backward-compatible: Dispatch() no cambia su firma y sigue siendo la llamada
// estándar en el flujo principal de runScan.
func (d *L7Dispatcher) DispatchWithContext(
	host string,
	openPort int,
	openProtocol string,
	timeout time.Duration,
	dialer proxy.ContextDialer,
	pivotCtx PivotContext,
) []rules.Finding {
	findings := d.Dispatch(host, openPort, openProtocol, timeout, dialer)
	if pivotCtx.IsPivot && len(findings) > 0 {
		for i := range findings {
			findings[i].Context = fmt.Sprintf(
				"PIVOT via %s:%d (%s)",
				pivotCtx.ProxyHost, pivotCtx.ProxyPort, pivotCtx.ProxyType,
			)
		}
	}
	return findings
}

// ──────────────────────────────────────────────

// ExecuteL7Template ejecuta una regla L7 de manera segura y binaria contra un target.
//
// Mejoras respecto a la versión anterior:
//   - Usa proxy.ContextDialer para respetar --proxies (propagación completa).
//   - Soporta 4 tipos de matchers: hex, regex, contains, starts_with.
//   - La evidencia incluye texto legible cuando la respuesta es ASCII, hex en caso binario.
func ExecuteL7Template(target string, tmpl rules.L7Template, timeout time.Duration, dialer proxy.ContextDialer) []rules.Finding {
	var findings []rules.Finding

	addr := fmt.Sprintf("%s:%d", target, tmpl.Port)

	proto := tmpl.Protocol
	if proto == "" {
		proto = "tcp"
	}

	// 1. Establecer conexión respetando el proxy configurado (propagado desde --proxies).
	var conn net.Conn
	var err error

	if dialer != nil {
		dialCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		conn, err = dialer.DialContext(dialCtx, proto, addr)
	} else {
		conn, err = net.DialTimeout(proto, addr, timeout)
	}

	if err != nil {
		return findings // Puerto cerrado o proxy inalcanzable — degradación silenciosa
	}
	defer conn.Close()

	// 2. Tarpit Protection: Timeout absoluto de lectura/escritura (evita deadlocks).
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// 3. Inyectar Payloads del YAML.
	// Soporte dual: hex puro (ej. "504f4e470d0a") o string literal (ej. "PING\r\n").
	for _, rawPayload := range tmpl.Payloads {
		payloadBytes, decodeErr := rules.DecodeHex(rawPayload)
		if decodeErr != nil {
			// No es hex válido → tratar como string literal con escape sequences
			payloadBytes = []byte(strings.NewReplacer(
				`\r`, "\r",
				`\n`, "\n",
				`\t`, "\t",
			).Replace(rawPayload))
		}

		if _, writeErr := conn.Write(payloadBytes); writeErr != nil {
			return findings // Conexión reseteada por el servidor
		}
	}

	// 4. Leer respuesta cruda (máximo 4KB protegidos con io.LimitReader para prevenir Memory Exhaustion por Tarpits).
	buffer := make([]byte, 4096)
	lr := io.LimitReader(conn, 4096)
	n, readErr := lr.Read(buffer)
	if readErr != nil && n == 0 {
		return findings
	}
	responseBytes := buffer[:n]

	// 5. Evaluación de Matchers — Soporta: hex, regex, contains, starts_with.
	matched := false
	matchedOn := ""

	for _, matcher := range tmpl.Matchers {
		switch matcher.Type {

		case rules.MatcherTypeHex:
			// Evaluación BINARIA pura — ideal para protocolos binarios (SMB, RDP, Modbus…)
			expectedBytes, decErr := rules.DecodeHex(matcher.Value)
			if decErr != nil {
				continue
			}
			if bytes.Contains(responseBytes, expectedBytes) {
				matched = true
				matchedOn = fmt.Sprintf("HEX Match: %s", matcher.Value)
			}

		case rules.MatcherTypeRegex:
			// Evaluación Regex — para protocolos de texto plano conocidos (SSH, Redis, HTTP…)
			re, reErr := regexp.Compile(matcher.Value)
			if reErr != nil {
				continue
			}
			if re.Match(responseBytes) {
				matched = true
				matchedOn = fmt.Sprintf("Regex Match: %s", matcher.Value)
			}

		case rules.MatcherTypeContains:
			// Substring case-insensitive — el más sencillo, perfecto para banners y proxies
			if strings.Contains(
				strings.ToLower(string(responseBytes)),
				strings.ToLower(matcher.Value),
			) {
				matched = true
				matchedOn = fmt.Sprintf("Contains Match: %q", matcher.Value)
			}

		case rules.MatcherTypeStartsWith:
			// Prefijo case-insensitive — útil para handshakes con cabecera fija
			if strings.HasPrefix(
				strings.ToLower(string(responseBytes)),
				strings.ToLower(matcher.Value),
			) {
				matched = true
				matchedOn = fmt.Sprintf("StartsWith Match: %q", matcher.Value)
			}
		}

		if matched {
			break // Short-circuit: primer matcher que coincide es suficiente
		}
	}

	if !matched {
		return findings
	}

	// 6. Construir evidencia — texto legible si es ASCII, hex si es binario
	evidence := buildL7Evidence(responseBytes)

	findings = append(findings, rules.Finding{
		Host:        target,
		Port:        tmpl.Port,
		RuleID:      tmpl.ID,
		RuleName:    tmpl.Name,
		Severity:    tmpl.Severity,
		Confidence:  "confirmed", // Interacción L7 exitosa → detección confirmada al 100%
		Description: tmpl.Description,
		MatchedOn:   matchedOn,
		Evidence:    evidence,
	})

	return findings
}

// buildL7Evidence construye la cadena de evidencia para un finding L7.
// Si la respuesta tiene ≤30% de bytes no imprimibles, la muestra como texto.
// En caso contrario, la muestra solo como hex (datos binarios).
func buildL7Evidence(responseBytes []byte) string {
	if len(responseBytes) == 0 {
		return "Raw L7 Response: (empty)"
	}

	hexEvidence := fmt.Sprintf("%x", responseBytes)
	if len(hexEvidence) > 400 {
		hexEvidence = hexEvidence[:400] + "...[truncado]"
	}

	// Calcular proporción de bytes no imprimibles
	nonPrintable := 0
	for _, c := range responseBytes {
		if c < 32 && c != '\n' && c != '\r' && c != '\t' {
			nonPrintable++
		}
	}

	if float64(nonPrintable)/float64(len(responseBytes)) <= 0.30 {
		// Respuesta de texto legible → mostrar ambos
		textResponse := strings.Map(func(r rune) rune {
			if r < 32 && r != '\n' && r != '\r' {
				return '.'
			}
			return r
		}, string(responseBytes))
		if len(textResponse) > 300 {
			textResponse = textResponse[:300] + "...[truncado]"
		}
		return "Text Response:\n" + textResponse + "\n\nRaw L7 Response (Hex):\n" + hexEvidence
	}

	// Datos binarios — solo hex
	return "Raw L7 Response (Hex):\n" + hexEvidence
}
