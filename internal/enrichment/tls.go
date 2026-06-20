package enrichment

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/raptor-recon/raptor/internal/proxy"
	"github.com/raptor-recon/raptor/internal/rules"
)

// CheckTLS realiza un handshake TLS ligero usando la librería estándar de Go.
// Acepta un proxy.ContextDialer opcional para enrutar la conexión TCP subyacente.
func CheckTLS(host string, port int, timeout time.Duration, dialer proxy.ContextDialer) []rules.Finding {
	var findings []rules.Finding

	addr := fmt.Sprintf("%s:%d", host, port)

	// 1. Establecer conexión TCP subyacente (con soporte de proxy)
	conn, err := dialWithProxy(context.Background(), addr, timeout, dialer)
	if err != nil {
		return findings
	}
	defer conn.Close()

	// Configuración TLS laxa para permitir conexiones inseguras y extraer info
	config := &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- Intentional for scanner
		MinVersion:         tls.VersionTLS10, // Permitir versiones antiguas para detectarlas
		MaxVersion:         tls.VersionTLS13,
	}

	// 2. Realizar el handshake TLS
	_ = conn.SetDeadline(time.Now().Add(timeout)) // CRÍTICO: Evitar que el handshake se quede colgado eternamente
	tlsConn := tls.Client(conn, config)
	err = tlsConn.Handshake()
	if err != nil {
		// No es un puerto TLS válido o falló el handshake
		return findings
	}

	state := tlsConn.ConnectionState()

	// 3. Evaluar versiones obsoletas (TLS 1.0 y 1.1)
	if state.Version == tls.VersionTLS10 || state.Version == tls.VersionTLS11 {
		versionStr := "TLS 1.0"
		if state.Version == tls.VersionTLS11 {
			versionStr = "TLS 1.1"
		}
		findings = append(findings, rules.Finding{
			Host:        host,
			Port:        port,
			RuleID:      "TLS-OBSOLETE-VERSION",
			RuleName:    "Uso de " + versionStr,
			Severity:    rules.SeverityHigh,
			Description: fmt.Sprintf("El servicio soporta %s, el cual es obsoleto y vulnerable a ataques como BEAST, POODLE.", versionStr),
			Remediation: "Deshabilitar TLS 1.0 y TLS 1.1 en el servidor. Configurar TLS 1.2 o superior como versión mínima.",
		})
	}

	// 4. Evaluar certificados
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		now := time.Now()

		if now.After(cert.NotAfter) {
			findings = append(findings, rules.Finding{
				Host:        host,
				Port:        port,
				RuleID:      "TLS-CERT-EXPIRED",
				RuleName:    "Certificado SSL/TLS Expirado",
				Severity:    rules.SeverityCritical,
				Description: fmt.Sprintf("El certificado SSL/TLS expiró el %s.", cert.NotAfter.Format("2006-01-02")),
				Remediation: "Renovar e instalar un nuevo certificado SSL/TLS inmediatamente.",
			})
		} else if cert.NotAfter.Sub(now) < 15*24*time.Hour { // Expira en menos de 15 días
			daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
			findings = append(findings, rules.Finding{
				Host:        host,
				Port:        port,
				RuleID:      "TLS-CERT-EXPIRING",
				RuleName:    "Certificado SSL/TLS próximo a expirar",
				Severity:    rules.SeverityHigh,
				Description: fmt.Sprintf("El certificado SSL/TLS expirará en %d días (fecha: %s).", daysLeft, cert.NotAfter.Format("2006-01-02")),
				Remediation: "Planificar la renovación del certificado SSL/TLS antes de que expire.",
			})
		}

		// Extracción OSINT pasiva de dominios (SANs y Common Name)
		var domains []string
		if cert.Subject.CommonName != "" {
			domains = append(domains, cert.Subject.CommonName)
		}
		domains = append(domains, cert.DNSNames...)

		// Eliminar duplicados simples
		uniqueDomains := make(map[string]bool)
		var cleanDomains []string
		for _, d := range domains {
			if !uniqueDomains[d] && d != "" {
				uniqueDomains[d] = true
				cleanDomains = append(cleanDomains, d)
			}
		}

		if len(cleanDomains) > 0 {
			findings = append(findings, rules.Finding{
				Host:        host,
				Port:        port,
				RuleID:      "TLS-DOMAINS-DISCOVERED",
				RuleName:    "Dominios extraídos de certificado TLS",
				Severity:    rules.SeverityInfo,
				Description: strings.Join(cleanDomains, ","),
			})
		}
	}

	return findings
}
