package enrichment

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/raptor-recon/raptor/internal/rules"
)

// Las rutas estáticas en memoria garantizan un único binario (drop and go).
var microWordlist = []string{
	"/.env",
	"/.git/config",
	"/admin/",
	"/server-status",
	"/phpinfo.php",
	"/actuator/health",
	"/.aws/credentials",
	"/swagger-ui.html",
}

// buildHTTPClient construye un http.Client configurado con el proxy si se proporciona una URL.
// proxyURL puede ser "" para conexión directa, o "http://host:port", "socks5://host:port", etc.
func buildHTTPClient(timeout time.Duration, proxyURL string) *http.Client {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // #nosec G402
		DisableKeepAlives: true,
	}

	if proxyURL != "" {
		if parsedProxy, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(parsedProxy)
		}
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		// Evitar seguir demasiados redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// CheckWebFingerprint realiza un Fuzzing quirúrgico y Tech Fingerprinting a rutas críticas
// y dinámicas de las reglas. Acepta proxyURL opcional para enrutar el tráfico HTTP.
func CheckWebFingerprint(host string, port int, isTLS bool, timeout time.Duration, ruleSetRules []rules.Rule, statusChan chan<- string, proxyURL string) []rules.Finding {
	var findings []rules.Finding

	protocol := "http"
	if isTLS {
		protocol = "https"
	}

	baseURL := fmt.Sprintf("%s://%s:%d", protocol, host, port)

	// Cliente HTTP con soporte de proxy integrado
	client := buildHTTPClient(timeout, proxyURL)

	// 1. Tech Fingerprinting (Extracción de Cabeceras en la raíz)
	req, err := http.NewRequest("HEAD", baseURL+"/", nil)
	if err == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) RaptorRecon")
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()

			server := resp.Header.Get("Server")
			poweredBy := resp.Header.Get("X-Powered-By")

			if server != "" || poweredBy != "" {
				desc := "Tecnologías detectadas en cabeceras HTTP."
				if server != "" {
					desc += fmt.Sprintf(" Server: %s.", server)
				}
				if poweredBy != "" {
					desc += fmt.Sprintf(" X-Powered-By: %s.", poweredBy)
				}

				// Capturar headers crudos como evidencia
				var headersBuilder strings.Builder
				for k, v := range resp.Header {
					headersBuilder.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
				}
				evidence := headersBuilder.String()
				if len(evidence) > 500 {
					evidence = evidence[:500] + "\n...[truncado]"
				}

				findings = append(findings, rules.Finding{
					Host:        host,
					Port:        port,
					RuleID:      "WEB-TECH-FINGERPRINT",
					RuleName:    "Exposición de Tecnologías Web",
					Severity:    rules.SeverityInfo,
					Confidence:  "high",
					Description: desc,
					Remediation: "Configurar el servidor web para omitir las cabeceras Server y X-Powered-By para reducir la superficie de información.",
					Evidence:    "Raw HTTP Headers:\n" + evidence,
				})
			}
		}
	}

	// 2. Micro-Fuzzing Quirúrgico
	for _, path := range microWordlist {
		targetURL := baseURL + path
		if statusChan != nil {
			select {
			case statusChan <- targetURL:
			default:
			}
		}
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) RaptorRecon")
		resp, err := client.Do(req)

		if err != nil {
			continue // Degradación silenciosa (timeout, conexión reseteada)
		}

		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096)) // Leer solo 4KB
			bodyStr := string(body)

			// Falso positivo check: asegurar que no es una página de "Soft 404"
			if !strings.Contains(strings.ToLower(bodyStr), "404") && !strings.Contains(strings.ToLower(bodyStr), "not found") {

				// Validación estricta de contenido por ruta
				isValid := false
				ruleName := "Archivo Sensible Expuesto"
				severity := rules.SeverityHigh
				desc := fmt.Sprintf("La ruta %s devolvió un 200 OK y parece contener información sensible.", path)

				if path == "/.env" && (strings.Contains(bodyStr, "DB_") || strings.Contains(bodyStr, "APP_") || strings.Contains(bodyStr, "SECRET_") || strings.Contains(bodyStr, "AWS_")) {
					isValid = true
					ruleName = "Exposición de Archivo .env"
					severity = rules.SeverityCritical
				} else if path == "/.git/config" && strings.Contains(bodyStr, "[core]") {
					isValid = true
					ruleName = "Exposición de Repositorio Git"
					severity = rules.SeverityCritical
				} else if path == "/admin/" && (strings.Contains(strings.ToLower(bodyStr), "admin") || strings.Contains(strings.ToLower(bodyStr), "login") || strings.Contains(strings.ToLower(bodyStr), "password")) {
					isValid = true
					ruleName = "Panel de Administración Expuesto"
					severity = rules.SeverityMedium
				} else if path == "/server-status" && strings.Contains(bodyStr, "Apache Server Status") {
					isValid = true
					ruleName = "Exposición de Apache Server-Status"
				} else if path == "/phpinfo.php" && strings.Contains(bodyStr, "phpinfo()") {
					isValid = true
					ruleName = "Exposición de PHPInfo"
				} else if path == "/actuator/health" && strings.Contains(bodyStr, "status") {
					isValid = true
					ruleName = "Exposición de Spring Boot Actuator"
				} else if path == "/.aws/credentials" && (strings.Contains(bodyStr, "aws_access_key_id")) {
					isValid = true
					ruleName = "Exposición de Credenciales AWS"
					severity = rules.SeverityCritical
				} else if path == "/swagger-ui.html" && strings.Contains(strings.ToLower(bodyStr), "swagger") {
					isValid = true
					ruleName = "Exposición de Documentación API (Swagger)"
					severity = rules.SeverityMedium
				}

				if isValid {
					evidence := bodyStr
					if len(evidence) > 500 {
						evidence = evidence[:500] + "\n...[truncado]"
					}
					findings = append(findings, rules.Finding{
						Host:        host,
						Port:        port,
						RuleID:      "WEB-FUZZ-SENSITIVE",
						RuleName:    ruleName,
						Severity:    severity,
						Confidence:  "confirmed",
						Description: desc,
						Remediation: "Restringir el acceso a esta ruta, eliminar archivos sensibles expuestos y configurar el servidor web para denegar acceso a archivos/directorios ocultos.",
						Evidence:    "HTTP Response Body snippet:\n" + evidence,
					})
				}
			}
		}
		_ = resp.Body.Close()
	}

	// 3. Fuzzing Dinámico de las Reglas (YAML http_paths)
	for _, rule := range ruleSetRules {
		if len(rule.Match.HTTPPaths) == 0 {
			continue
		}

		// Optimización: Si la regla especifica puertos, solo evaluar si el puerto coincide
		if len(rule.Match.Ports) > 0 {
			portMatch := false
			for _, p := range rule.Match.Ports {
				if p == port {
					portMatch = true
					break
				}
			}
			if !portMatch {
				continue
			}
		}

		ruleMatched := false

		for _, path := range rule.Match.HTTPPaths {
			if ruleMatched {
				break
			}
			targetURL := baseURL + path
			if statusChan != nil {
				select {
				case statusChan <- targetURL:
				default:
				}
			}
			req, err := http.NewRequest("GET", targetURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) RaptorRecon")
			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			if resp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				bodyStr := string(body)

				// Falso positivo check para páginas Soft 404
				if !strings.Contains(strings.ToLower(bodyStr), "404") && !strings.Contains(strings.ToLower(bodyStr), "not found") {

					// Validación estricta: Si la regla define banners, al menos uno debe estar en el Body o Headers HTTP
					bannerMatched := true
					if len(rule.Match.Banners) > 0 {
						bannerMatched = false
						lowerBody := strings.ToLower(bodyStr)

						var headersBuilder strings.Builder
						for k, v := range resp.Header {
							headersBuilder.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
						}
						lowerHeaders := strings.ToLower(headersBuilder.String())

						for _, b := range rule.Match.Banners {
							lb := strings.ToLower(b)
							if strings.Contains(lowerBody, lb) || strings.Contains(lowerHeaders, lb) {
								bannerMatched = true
								break
							}
						}
					}

					if !bannerMatched {
						_ = resp.Body.Close()
						continue // Es un Soft 404 encubierto o catch-all router
					}

					evidence := bodyStr
					if len(evidence) > 500 {
						evidence = evidence[:500] + "\n...[truncado]"
					}

					findings = append(findings, rules.Finding{
						Host:        host,
						Port:        port,
						RuleID:      rule.ID,
						RuleName:    rule.Name,
						Severity:    rule.Severity,
						Context:     rule.Context,
						Confidence:  rule.Confidence,
						CVSSBase:    rule.CVSSBase,
						Tags:        rule.Tags,
						Description: fmt.Sprintf("Detección Dinámica Web: La ruta %s devolvió 200 OK. %s", path, rule.Description),
						Remediation: rule.Remediation,
						Evidence:    "HTTP Response Body snippet:\n" + evidence,
						Mitre:       rule.Mitre,
						Compliance:  rule.Compliance,
						MatchedOn:   "http_paths: " + path,
					})
					ruleMatched = true
				}
			}
			_ = resp.Body.Close()
		}
	}

	return findings
}
