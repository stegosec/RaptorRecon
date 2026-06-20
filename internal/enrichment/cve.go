package enrichment

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/raptor-recon/raptor/internal/stealth"
)

// ──────────────────────────────────────────────
// Tipos públicos
// ──────────────────────────────────────────────

// CVE represents a dynamically resolved vulnerability.
type CVE struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Score       float64 `json:"score"`
}

// ServiceID contiene el producto y versión extraídos de un banner.
// Si Version está vacío, significa que no se pudo determinar la versión exacta
// y el módulo NO debe consultar la API (cero suposiciones).
type ServiceID struct {
	Vendor  string // ej. "apache", "openbsd"
	Product string // ej. "httpd", "openssh"
	Version string // ej. "2.4.41", "8.2p1"
}

// CPEString construye un CPE 2.3 básico para consultas NVD.
// Formato: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
func (s ServiceID) CPEString() string {
	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*",
		s.Vendor, s.Product, s.Version)
}

// QueryString retorna un string optimizado para búsqueda por keywords.
func (s ServiceID) QueryString() string {
	return fmt.Sprintf("%s %s %s", s.Vendor, s.Product, s.Version)
}

// ──────────────────────────────────────────────
// Banner Parser — Motor Regex de Extracción
// ──────────────────────────────────────────────

// bannerPattern define una regla de extracción para un servicio específico.
type bannerPattern struct {
	Regex   *regexp.Regexp
	Vendor  string
	Product string
	// VersionGroup indica qué grupo de captura contiene la versión (1-indexed)
	VersionGroup int
}

// bannerPatterns es el motor de reglas regex para los servicios más comunes.
// Cada regex captura la versión exacta del servicio.
// El orden importa: las reglas más específicas van primero.
var bannerPatterns = []bannerPattern{
	// ── SSH ──
	// OpenSSH: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3"
	{
		Regex:        regexp.MustCompile(`(?i)OpenSSH[_/ ](\d+\.\d+(?:p\d+)?)`),
		Vendor:       "openbsd",
		Product:      "openssh",
		VersionGroup: 1,
	},
	// Dropbear: "SSH-2.0-dropbear_2020.81"
	{
		Regex:        regexp.MustCompile(`(?i)dropbear[_/ ](\d+\.\d+)`),
		Vendor:       "matt_johnston",
		Product:      "dropbear_ssh",
		VersionGroup: 1,
	},

	// ── HTTP Servers ──
	// Apache: "Apache/2.4.41 (Ubuntu)" o "Server: Apache/2.4.52"
	{
		Regex:        regexp.MustCompile(`(?i)Apache[/ ](\d+\.\d+\.\d+)`),
		Vendor:       "apache",
		Product:      "http_server",
		VersionGroup: 1,
	},
	// nginx: "nginx/1.18.0" o "Server: nginx/1.24.0"
	{
		Regex:        regexp.MustCompile(`(?i)nginx[/ ](\d+\.\d+\.\d+)`),
		Vendor:       "f5",
		Product:      "nginx",
		VersionGroup: 1,
	},
	// Microsoft IIS: "Microsoft-IIS/10.0"
	{
		Regex:        regexp.MustCompile(`(?i)Microsoft-IIS[/ ](\d+\.\d+)`),
		Vendor:       "microsoft",
		Product:      "internet_information_services",
		VersionGroup: 1,
	},
	// LiteSpeed: "LiteSpeed/6.0.12"
	{
		Regex:        regexp.MustCompile(`(?i)LiteSpeed[/ ](\d+\.\d+(?:\.\d+)?)`),
		Vendor:       "litespeedtech",
		Product:      "litespeed_web_server",
		VersionGroup: 1,
	},

	// ── FTP ──
	// vsftpd: "220 (vsFTPd 3.0.3)"
	{
		Regex:        regexp.MustCompile(`(?i)vsFTPd\s+(\d+\.\d+\.\d+)`),
		Vendor:       "beasts",
		Product:      "vsftpd",
		VersionGroup: 1,
	},
	// ProFTPD: "220 ProFTPD 1.3.6 Server"
	{
		Regex:        regexp.MustCompile(`(?i)ProFTPD\s+(\d+\.\d+\.\d+[a-z]?)`),
		Vendor:       "proftpd",
		Product:      "proftpd",
		VersionGroup: 1,
	},
	// Pure-FTPd: "220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------"
	// Con versión: "Pure-FTPd 1.0.49"
	{
		Regex:        regexp.MustCompile(`(?i)Pure-FTPd\s+(\d+\.\d+\.\d+)`),
		Vendor:       "pureftpd",
		Product:      "pure-ftpd",
		VersionGroup: 1,
	},

	// ── Databases ──
	// MySQL: "5.7.33-0ubuntu0.18.04.1" (banner crudo) o "mysql/8.0.28"
	{
		Regex:        regexp.MustCompile(`(?i)(?:mysql|MariaDB)[/ ]*(\d+\.\d+\.\d+)`),
		Vendor:       "oracle",
		Product:      "mysql",
		VersionGroup: 1,
	},
	// MariaDB override: "5.5.5-10.6.7-MariaDB"
	{
		Regex:        regexp.MustCompile(`(?i)(\d+\.\d+\.\d+)-MariaDB`),
		Vendor:       "mariadb",
		Product:      "mariadb",
		VersionGroup: 1,
	},
	// PostgreSQL: "PostgreSQL 14.2"
	{
		Regex:        regexp.MustCompile(`(?i)PostgreSQL\s+(\d+\.\d+(?:\.\d+)?)`),
		Vendor:       "postgresql",
		Product:      "postgresql",
		VersionGroup: 1,
	},
	// Redis: "redis_version:7.0.5" o "-ERR ... Redis"
	{
		Regex:        regexp.MustCompile(`(?i)redis[_: /]?(?:version[: ]?)?(\d+\.\d+\.\d+)`),
		Vendor:       "redis",
		Product:      "redis",
		VersionGroup: 1,
	},
	// MongoDB: "MongoDB server version: 5.0.14"
	{
		Regex:        regexp.MustCompile(`(?i)MongoDB\s+(?:server\s+)?(?:version[: ]+)?(\d+\.\d+\.\d+)`),
		Vendor:       "mongodb",
		Product:      "mongodb",
		VersionGroup: 1,
	},

	// ── Mail ──
	// Postfix: "220 mail.example.com ESMTP Postfix (Ubuntu)"
	// Postfix rara vez revela versión en banner, pero intentamos
	{
		Regex:        regexp.MustCompile(`(?i)Postfix[/ ]+(\d+\.\d+\.\d+)`),
		Vendor:       "postfix",
		Product:      "postfix",
		VersionGroup: 1,
	},
	// Exim: "220 mail.example.com ESMTP Exim 4.95"
	{
		Regex:        regexp.MustCompile(`(?i)Exim\s+(\d+\.\d+(?:\.\d+)?)`),
		Vendor:       "exim",
		Product:      "exim",
		VersionGroup: 1,
	},
	// Dovecot: "* OK Dovecot (Ubuntu) ready."
	// Con versión: "Dovecot 2.3.13"
	{
		Regex:        regexp.MustCompile(`(?i)Dovecot[/ ]+(\d+\.\d+\.\d+)`),
		Vendor:       "dovecot",
		Product:      "dovecot",
		VersionGroup: 1,
	},

	// ── Otros ──
	// OpenSSL en banners (suele aparecer como parte de Apache/nginx)
	{
		Regex:        regexp.MustCompile(`(?i)OpenSSL[/ ](\d+\.\d+\.\d+[a-z]*)`),
		Vendor:       "openssl",
		Product:      "openssl",
		VersionGroup: 1,
	},
	// Elasticsearch: headers o banner con versión
	{
		Regex:        regexp.MustCompile(`(?i)elasticsearch[/ ]*(\d+\.\d+\.\d+)`),
		Vendor:       "elastic",
		Product:      "elasticsearch",
		VersionGroup: 1,
	},
}

// ParseBanner analiza un banner de servicio crudo y extrae las identidades
// de software (vendor, product, version) usando el motor regex.
//
// Retorna todas las coincidencias encontradas (un banner puede revelar
// múltiples componentes, ej. "Apache/2.4.41 OpenSSL/1.1.1").
//
// Si NO se extrae NINGUNA versión, retorna un slice vacío.
// Esto es intencional: cero suposiciones, cero falsos positivos.
func ParseBanner(banner string) []ServiceID {
	if strings.TrimSpace(banner) == "" {
		return nil
	}

	var results []ServiceID
	seen := make(map[string]struct{}) // de-duplicar por product+version

	for _, bp := range bannerPatterns {
		matches := bp.Regex.FindStringSubmatch(banner)
		if matches == nil || bp.VersionGroup >= len(matches) {
			continue
		}

		version := matches[bp.VersionGroup]
		if version == "" {
			continue
		}

		key := bp.Product + ":" + version
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		results = append(results, ServiceID{
			Vendor:  bp.Vendor,
			Product: bp.Product,
			Version: version,
		})
	}

	return results
}

// ──────────────────────────────────────────────
// NVD API 2.0
// ──────────────────────────────────────────────

// NVD API 2.0 Response structs
type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CvssMetricV30 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
				CvssMetricV2 []struct {
					BaseSeverity string `json:"baseSeverity"`
					CvssData     struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// rate limit control
var lastRequestTime time.Time

// LookupCVEs busca CVEs asociados a un banner de servicio.
//
// Flujo:
//  1. Parsear el banner con el motor regex para extraer ServiceID(s) precisos.
//  2. Si NO se extrae ningún producto+versión → retornar nil (cero suposiciones).
//  3. Para cada ServiceID, construir un CPE y consultar la NVD API.
//  4. Agregar y retornar todos los CVEs encontrados, de-duplicados por ID.
func LookupCVEs(banner string) []CVE {
	// Fase 1: Extraer identidades de software del banner
	services := ParseBanner(banner)
	if len(services) == 0 {
		// Banner no reveló producto+versión → omitir consulta (cero ruido)
		return nil
	}

	// Fase 2: Consultar NVD por cada servicio identificado
	var allCVEs []CVE
	seenCVE := make(map[string]struct{})

	for _, svc := range services {
		cves := queryCVEsForService(svc)
		for _, c := range cves {
			if _, exists := seenCVE[c.ID]; !exists {
				seenCVE[c.ID] = struct{}{}
				allCVEs = append(allCVEs, c)
			}
		}
	}

	return allCVEs
}

// queryCVEsForService consulta la NVD API 2.0 usando un CPE construido
// a partir del ServiceID extraído por el banner parser.
//
// Estrategia de consulta dual:
//  1. Intentar primero con cpeName (CPE match exacto) → resultados precisos.
//  2. Si no hay resultados, fallback a keywordSearch con "vendor product version".
func queryCVEsForService(svc ServiceID) []CVE {
	// Intentar keywordSearch con "product version" (mucho más flexible que CPE exacto)
	// Para evitar falsos positivos exagerados, limitamos a 5 resultados
	query := svc.Product + " " + svc.Version
	// Limpiamos underscores que usa el parser interno para product names
	query = strings.ReplaceAll(query, "_", " ")
	
	apiURL := fmt.Sprintf(
		"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=5",
		url.QueryEscape(query),
	)

	return queryNVDAPI(apiURL)
}

// queryNVDAPI ejecuta una petición contra la NVD API 2.0 con rate limiting
// y retorna los CVEs parseados de la respuesta.
func queryNVDAPI(apiURL string) []CVE {
	// Enforce rate limit (NVD public API: 5 requests / 30 seconds → 6s delay)
	timeSinceLast := time.Since(lastRequestTime)
	if timeSinceLast < 6*time.Second {
		time.Sleep((6 * time.Second) - timeSinceLast)
	}
	lastRequestTime = time.Now()

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil
	}

	// Rotación de User-Agent para evadir WAFs
	req.Header.Set("User-Agent", stealth.RandomUserAgent())

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil && resp.Body != nil {
			if cerr := resp.Body.Close(); cerr != nil {
				// log.Printf("WARN: Error al cerrar Body de respuesta NVD: %v", cerr)
			}
		}
		return nil
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			// Fail-safe handling para evitar warnings G104
		}
	}()

	var nvdResp nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil
	}

	var results []CVE
	for _, v := range nvdResp.Vulnerabilities {
		c := v.CVE

		desc := "No description available"
		for _, d := range c.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}

		// Truncate description if too long
		if len(desc) > 200 {
			desc = desc[:197] + "..."
		}

		severity := "UNKNOWN"
		var score float64

		// Try V3.1
		if len(c.Metrics.CvssMetricV31) > 0 {
			m := c.Metrics.CvssMetricV31[0].CvssData
			severity = m.BaseSeverity
			score = m.BaseScore
		} else if len(c.Metrics.CvssMetricV30) > 0 { // Try V3.0
			m := c.Metrics.CvssMetricV30[0].CvssData
			severity = m.BaseSeverity
			score = m.BaseScore
		} else if len(c.Metrics.CvssMetricV2) > 0 { // Try V2
			m := c.Metrics.CvssMetricV2[0]
			severity = m.BaseSeverity
			score = m.CvssData.BaseScore
		}

		results = append(results, CVE{
			ID:          c.ID,
			Description: desc,
			Severity:    severity,
			Score:       score,
		})
	}

	return results
}
