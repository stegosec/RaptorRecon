// Package pivot implementa Proxy Pivot Detection: detecta proxies HTTP/SOCKS5 abiertos
// y lanza sub-escaneos a través de ellos para descubrir servicios ocultos.
//
// Diseño sin dependencias circulares:
//   - pivot → proxy (para ContextDialer)
//   - pivot → rules  (para Finding, Severity)
//   - scanner → pivot (NO — pivot no importa scanner)
//   - main → pivot, scanner (orquesta ambos)
//
// El motor de sub-escaneo está implementado directamente en este paquete
// (scanViaPivot) para evitar la dependencia pivot→scanner.
package pivot

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/raptor-recon/raptor/internal/proxy"
	"github.com/raptor-recon/raptor/internal/rules"
)

// ──────────────────────────────────────────────
// Tipos públicos
// ──────────────────────────────────────────────

// PivotMode define la política operativa del motor de pivot.
type PivotMode int

const (
	// PivotModeDisabled — pivot inactivo. Default seguro para uso CLI sin flags especiales.
	PivotModeDisabled PivotMode = iota
	// PivotModeAuto — activado por --auto. L1+L2 sin prompts, cero intervención.
	PivotModeAuto
	// PivotModeTUI — activado en el wizard interactivo. Encola candidatos y pregunta al usuario al finalizar.
	PivotModeTUI
	// PivotModeManual — activado por --proxy-pivot. L1 (y L2 si --pivot-subnet). Sin prompts.
	PivotModeManual
)

// PivotLevel controla qué niveles de reconocimiento se ejecutan.
// Los niveles son acumulables: L1 es el mínimo, L2 y L3 son opt-in.
type PivotLevel struct {
	SameIP bool   // L1: siempre true cuando hay pivot activo
	Subnet bool   // L2: subred /24 del proxy. Automático en --auto, manual con --pivot-subnet
	Target string // L3: CIDR explícito via --pivot-target. Vacío = inactivo.
}

// Config agrupa toda la configuración del motor de pivot.
type Config struct {
	Mode       PivotMode
	Levels     PivotLevel
	PivotPorts []int         // Puertos a escanear en L1/L2 a través del proxy
	ProxyPorts []int         // Puertos vigilados para detectar proxies durante el escaneo principal
	Workers    int           // Workers para el sub-escaneo (max 100, default 50)
	Timeout    time.Duration // Timeout por conexión en el sub-escaneo
}

// Candidate representa un proxy detectado durante el escaneo principal
// que puede ser usado como túnel para pivot.
type Candidate struct {
	Host      string // IP del host que corre el proxy
	Port      int    // Puerto donde responde el proxy
	ProxyType string // "http-connect" | "socks5" — determinado en CheckAndPivot
}

// PivotFinding extiende rules.Finding con metadatos de pivot.
// Incluye el proxy usado como vector y la visibilidad del servicio detectado.
type PivotFinding struct {
	rules.Finding
	ProxyHost  string `json:"proxy_host"`
	ProxyPort  int    `json:"proxy_port"`
	// Visibility clasifica el hallazgo respecto al escaneo directo:
	//   "pivot-only" — servicio INVISIBLE al escaneo directo (hidden by firewall/loopback)
	//   "both"       — servicio accesible tanto directamente como vía proxy (confirmación)
	Visibility string `json:"visibility"`
}

// Result contiene todos los hallazgos de una sesión de pivot completa.
type Result struct {
	Proxy       Candidate
	L1Findings  []PivotFinding // L1: misma IP — puertos solo visibles vía proxy
	L2Findings  []PivotFinding // L2: subred /24 — hosts internos solo alcanzables vía proxy
	L3Findings  []PivotFinding // L3: rango explícito
	DirectPorts map[int]bool   // Set de puertos ya conocidos del escaneo directo (para diff)
}

// AllFindings retorna todos los findings de todos los niveles en orden L1→L2→L3.
func (r *Result) AllFindings() []PivotFinding {
	all := make([]PivotFinding, 0, len(r.L1Findings)+len(r.L2Findings)+len(r.L3Findings))
	all = append(all, r.L1Findings...)
	all = append(all, r.L2Findings...)
	all = append(all, r.L3Findings...)
	return all
}

// openPort es el resultado interno de un probe TCP exitoso.
type openPort struct {
	host     string
	port     int
	protocol string
}

// ──────────────────────────────────────────────
// Puertos por defecto
// ──────────────────────────────────────────────

// DefaultProxyPorts son los puertos vigilados durante el escaneo principal
// para detectar proxies candidatos a pivot.
var DefaultProxyPorts = []int{1080, 3128, 8080, 8118}

// DefaultPivotPorts son los puertos escaneados a través del proxy en L1 y L2.
// Cubrimos los servicios más críticos que suelen estar en loopback o detrás de firewall.
var DefaultPivotPorts = []int{21, 22, 23, 80, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017}

// ──────────────────────────────────────────────
// API pública
// ──────────────────────────────────────────────

// IsProxyPort reporta si un puerto es un proxy conocido a vigilar durante el escaneo.
// Usa DefaultProxyPorts si cfg.ProxyPorts está vacío.
func IsProxyPort(port int, cfg Config) bool {
	ports := cfg.ProxyPorts
	if len(ports) == 0 {
		ports = DefaultProxyPorts
	}
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// CheckAndPivot es la función principal del motor de pivot.
//
// Flujo:
//  1. Verificar que el proxy acepta CONNECT (HTTP) o no requiere auth (SOCKS5).
//  2. Si falla → retorna (nil, nil) — silencioso, no interrumpe el flujo principal.
//  3. Construir ContextDialer apuntando al proxy verificado.
//  4. L1: Escanear la misma IP del proxy a través de él. Comparar con directPorts → PIVOT-ONLY/both.
//  5. L2 (si cfg.Levels.Subnet): Escanear subred /24 del proxy a través de él.
//  6. L3 (si cfg.Levels.Target != ""): Escanear CIDR explícito.
//
// IMPORTANTE: Esta función es blocking. Debe llamarse desde una goroutine con semáforo.
// En la arquitectura de Raptor, se llama desde runPivotPhase() DESPUÉS de asyncWg.Wait(),
// garantizando que directPorts (del hostMap) están 100% completos.
func CheckAndPivot(ctx context.Context, candidate Candidate, directHostMap map[string][]int, cfg Config) (*Result, error) {
	// Resolver timeout del sub-escaneo
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	verifyTimeout := timeout * 2
	if verifyTimeout > 8*time.Second {
		verifyTimeout = 8 * time.Second
	}

	// Paso 1: Verificar proxy — intentar SOCKS5 primero si es puerto 1080, luego HTTP CONNECT
	var proxyURL string
	if candidate.Port == 1080 && VerifySOCKS5(candidate.Host, candidate.Port, verifyTimeout) {
		candidate.ProxyType = "socks5"
		proxyURL = fmt.Sprintf("socks5://%s:%d", candidate.Host, candidate.Port)
	} else if VerifyHTTPConnect(candidate.Host, candidate.Port, verifyTimeout) {
		candidate.ProxyType = "http-connect"
		proxyURL = fmt.Sprintf("http://%s:%d", candidate.Host, candidate.Port)
	} else {
		// No es un proxy funcional — degradación silenciosa
		return nil, nil
	}

	// Paso 2: Construir ContextDialer que tuneliza a través del proxy detectado
	dialer, err := proxy.NewDialer(proxyURL, timeout)
	if err != nil {
		return nil, nil // No se puede crear el dialer — falla silenciosa
	}

	// Paso 3: Construir set de puertos directos global para el diff PIVOT-ONLY
	directSet := make(map[string]map[int]bool)
	for ip, ports := range directHostMap {
		directSet[ip] = make(map[int]bool)
		for _, p := range ports {
			directSet[ip][p] = true
		}
	}

	result := &Result{
		Proxy:       candidate,
		DirectPorts: directSet[candidate.Host],
	}

	pivotPorts := cfg.PivotPorts
	if len(pivotPorts) == 0 {
		pivotPorts = DefaultPivotPorts
	}

	workers := cfg.Workers
	if workers <= 0 || workers > 100 {
		workers = 50 // Motor reducido — no saturar el proxy
	}

	// Paso 4: L1 — Escanear la MISMA IP a través del proxy y su loopback (127.0.0.1)
	// Objetivo: descubrir puertos en loopback o detrás de firewall asimétrico
	if cfg.Levels.SameIP {
		open := scanViaPivot(ctx, candidate.Host, candidate.Port, candidate.ProxyType, dialer, []string{candidate.Host, "127.0.0.1"}, pivotPorts, workers, timeout)
		
		// Agrupar por puerto para deduplicar y priorizar 127.0.0.1 (SSRF) si ambos responden
		bestOpForPort := make(map[int]openPort)
		for _, op := range open {
			if existing, exists := bestOpForPort[op.port]; exists {
				// Si ya existe, solo sobreescribir si el actual es loopback
				if op.host == "127.0.0.1" && existing.host != "127.0.0.1" {
					bestOpForPort[op.port] = op
				}
			} else {
				bestOpForPort[op.port] = op
			}
		}

		for port, op := range bestOpForPort {
			// Si encontramos algo en 127.0.0.1, lo reportamos como perteneciente a candidate.Host
			reportedHost := op.host
			isLoopback := false
			if op.host == "127.0.0.1" {
				reportedHost = candidate.Host
				isLoopback = true
			}

			if !directSet[candidate.Host][port] {
				// ¡Puerto invisible al escaneo directo! El valor de este pivot.
				desc := fmt.Sprintf("Puerto %d/%s en %s es SOLO visible vía proxy %s:%d (%s). Posible regla de firewall asimétrica.",
					port, op.protocol, reportedHost, candidate.Host, candidate.Port, candidate.ProxyType)
				if isLoopback {
					desc = fmt.Sprintf("Puerto %d/%s está bindeado a localhost (127.0.0.1) pero expuesto a través del proxy %s:%d (%s) vía SSRF/Pivot.",
						port, op.protocol, candidate.Host, candidate.Port, candidate.ProxyType)
				}

				result.L1Findings = append(result.L1Findings, PivotFinding{
					Finding: rules.Finding{
						Host:     reportedHost,
						Port:     port,
						Service:  op.protocol,
						RuleID:   "PIVOT-EXPOSURE",
						RuleName: "Servicio Oculto — Solo Visible Vía Proxy",
						Severity: rules.SeverityCritical,
						Confidence: "confirmed",
						Description: desc,
						Remediation: "Revisar reglas de firewall y bindings de servicio. " +
							"Un servicio accesible vía proxy pero no directamente indica una " +
							"configuración de red asimétrica o un Server-Side Request Forgery interno que puede ser aprovechado por atacantes.",
						Context: fmt.Sprintf("PIVOT-L1 via %s:%d (%s)", candidate.Host, candidate.Port, candidate.ProxyType),
						Tags:    []string{"pivot", "proxy", "firewall-bypass", "ssrf"},
					},
					ProxyHost:  candidate.Host,
					ProxyPort:  candidate.Port,
					Visibility: "pivot-only",
				})
			}
		}
	}

	// Paso 5: L2 — Escanear subred /24 del proxy a través de él
	// Objetivo: descubrir hosts internos solo alcanzables vía proxy (red segmentada)
	if cfg.Levels.Subnet {
		subnetHostsRaw := subnet24Hosts(candidate.Host)
		var subnetHosts []string
		for _, h := range subnetHostsRaw {
			if h != candidate.Host { // Excluir al propio proxy para no duplicar L1
				subnetHosts = append(subnetHosts, h)
			}
		}

		if len(subnetHosts) > 0 {
			open := scanViaPivot(ctx, candidate.Host, candidate.Port, candidate.ProxyType, dialer, subnetHosts, pivotPorts, workers, timeout)
			for _, op := range open {
				if !directSet[op.host][op.port] {
					result.L2Findings = append(result.L2Findings, PivotFinding{
						Finding: rules.Finding{
							Host:     op.host,
							Port:     op.port,
							Service:  op.protocol,
							RuleID:   "PIVOT-SUBNET-EXPOSURE",
							RuleName: "Host Interno Solo Accesible Vía Proxy",
							Severity: rules.SeverityHigh,
							Confidence: "confirmed",
							Description: fmt.Sprintf(
								"Host %s:%d/%s solo accesible a través del proxy %s:%d. "+
									"Host invisible al escaneo directo — segmentación de red bypasseada.",
								op.host, op.port, op.protocol,
								candidate.Host, candidate.Port,
							),
							Remediation: "Revisar la configuración de red y ACLs del proxy. " +
								"El proxy actúa como puente a segmentos de red internos que " +
								"deberían estar aislados.",
							Context: fmt.Sprintf("PIVOT-L2 via %s:%d (%s)", candidate.Host, candidate.Port, candidate.ProxyType),
							Tags:    []string{"pivot", "proxy", "internal-network", "network-segmentation"},
						},
						ProxyHost:  candidate.Host,
						ProxyPort:  candidate.Port,
						Visibility: "pivot-only",
					})
				}
			}
		}
	}

	// Paso 6: L3 — Escanear CIDR explícito (solo si el usuario lo especificó)
	if cfg.Levels.Target != "" {
		_, ipnet, parseErr := net.ParseCIDR(cfg.Levels.Target)
		if parseErr == nil {
			l3Hosts := cidrHosts(ipnet, 1024) // Cap en 1024 hosts para evitar escaneos accidentales masivos
			if len(l3Hosts) > 0 {
				open := scanViaPivot(ctx, candidate.Host, candidate.Port, candidate.ProxyType, dialer, l3Hosts, pivotPorts, workers, timeout)
				for _, op := range open {
					if !directSet[op.host][op.port] {
						result.L3Findings = append(result.L3Findings, PivotFinding{
							Finding: rules.Finding{
								Host:     op.host,
								Port:     op.port,
								Service:  op.protocol,
								RuleID:   "PIVOT-RANGE-EXPOSURE",
								RuleName: "Host en Rango Explícito Solo Accesible Vía Proxy",
								Severity: rules.SeverityHigh,
								Confidence: "confirmed",
								Description: fmt.Sprintf(
									"Host %s:%d/%s en rango %s solo accesible vía proxy %s:%d.",
									op.host, op.port, op.protocol, cfg.Levels.Target,
									candidate.Host, candidate.Port,
								),
								Remediation: "Revisar segmentación de red en el rango " + cfg.Levels.Target + ". " +
									"El proxy expone acceso a rangos que deberían estar aislados.",
								Context: fmt.Sprintf("PIVOT-L3 via %s:%d (%s) → %s", candidate.Host, candidate.Port, candidate.ProxyType, cfg.Levels.Target),
								Tags:    []string{"pivot", "proxy", "explicit-range"},
							},
							ProxyHost:  candidate.Host,
							ProxyPort:  candidate.Port,
							Visibility: "pivot-only",
						})
					}
				}
			}
		}
	}

	return result, nil
}

// ──────────────────────────────────────────────
// Motor de sub-escaneo interno
// ──────────────────────────────────────────────

// scanViaPivot realiza TCP connect scan de puertos en los hosts dados
// usando el dialer proporcionado (que tuneliza a través del proxy detectado).
//
// Usa un pool reducido de workers (max 100) para no saturar el proxy
// ni generar tráfico sospechoso en la red interna.
func scanViaPivot(ctx context.Context, proxyHost string, proxyPort int, proxyType string, dialer proxy.ContextDialer, hosts []string, ports []int, workers int, timeout time.Duration) []openPort {
	type work struct {
		host string
		port int
	}

	// Pre-generar todos los targets para cargar el canal sin bloquear
	workCh := make(chan work, len(hosts)*len(ports)+1)
	for _, h := range hosts {
		for _, p := range ports {
			workCh <- work{host: h, port: p}
		}
	}
	close(workCh)

	var mu sync.Mutex
	var results []openPort
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range workCh {
				if ctx.Err() != nil {
					return
				}

				dialCtx, cancel := context.WithTimeout(ctx, timeout)
				conn, err := dialer.DialContext(dialCtx, "tcp", fmt.Sprintf("%s:%d", w.host, w.port))
				cancel()

				if err == nil {
					// Puerto abierto vía CONNECT TCP
					if tcpConn, ok := conn.(*net.TCPConn); ok {
						_ = tcpConn.SetLinger(0)
					}
					_ = conn.Close()
					mu.Lock()
					results = append(results, openPort{host: w.host, port: w.port, protocol: "tcp"})
					mu.Unlock()
				} else if proxyType == "http-connect" {
					// Fallback: Si el proxy bloquea CONNECT (ej. Squid para el puerto 80), intentar un GET absoluto.
					// Muchos proxies permiten 'GET http://host:port/' aunque bloqueen 'CONNECT'.
					_, fallbackCancel := context.WithTimeout(ctx, timeout)
					fallbackConn, fallbackErr := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", proxyHost, proxyPort), timeout)
					if fallbackErr == nil {
						_ = fallbackConn.SetDeadline(time.Now().Add(timeout))
						req := fmt.Sprintf("GET http://%s:%d/ HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: RaptorRecon/1.0\r\nProxy-Connection: close\r\n\r\n", w.host, w.port, w.host, w.port)
						_, _ = fallbackConn.Write([]byte(req))
						
						buf := make([]byte, 1024)
						n, _ := fallbackConn.Read(buf)
						if n > 0 {
							resp := string(buf[:n])
							// Si la respuesta es un error nativo de SQUID de conexión rechazada, entonces el puerto está cerrado internamente.
							// Si es cualquier código HTTP estándar de una aplicación web, está abierto.
							if strings.HasPrefix(resp, "HTTP/1.") && 
							   !strings.Contains(resp, "ERR_CONNECT_FAIL") && 
							   !strings.Contains(resp, "ERR_CONNECTION_REFUSED") &&
							   !strings.Contains(resp, "ERR_ACCESS_DENIED") && // Si Squid bloquea también el GET
							   !strings.Contains(resp, "503 Service Unavailable") &&
							   !strings.Contains(resp, "502 Bad Gateway") &&
							   !strings.Contains(resp, "504 Gateway Timeout") {
								// El servidor web detrás del proxy respondió!
								mu.Lock()
								results = append(results, openPort{host: w.host, port: w.port, protocol: "tcp"})
								mu.Unlock()
							}
						}
						_ = fallbackConn.Close()
					}
					fallbackCancel()
				}
			}
		}()
	}
	wg.Wait()
	return results
}

// ──────────────────────────────────────────────
// Helpers de red
// ──────────────────────────────────────────────

// subnet24Hosts genera todas las IPs del /24 al que pertenece la IP dada.
// Excluye .0 (red) y .255 (broadcast). Retorna hasta 254 hosts.
func subnet24Hosts(ip string) []string {
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return nil
	}
	hosts := make([]string, 0, 254)
	for i := 1; i < 255; i++ {
		hosts = append(hosts, fmt.Sprintf("%d.%d.%d.%d", parsed[0], parsed[1], parsed[2], i))
	}
	return hosts
}

// cidrHosts genera hasta maxHosts IPs de un bloque CIDR, excluyendo
// la dirección de red (.0) y broadcast (.255).
func cidrHosts(ipnet *net.IPNet, maxHosts int) []string {
	hosts := make([]string, 0, maxHosts)
	ip := cloneIP(ipnet.IP.Mask(ipnet.Mask))

	for ipnet.Contains(ip) && len(hosts) < maxHosts {
		ip4 := ip.To4()
		if ip4 != nil && ip4[3] != 0 && ip4[3] != 255 {
			hosts = append(hosts, ip.String())
		}
		incrementIP(ip)
	}
	return hosts
}

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func visibilityText(v string) string {
	if v == "pivot-only" {
		return "SOLO visible"
	}
	return "también visible"
}
