package risk

import (
	"math"
	"strings"

	"github.com/raptor-recon/raptor/internal/reporter"
)

// AnalyzeHost calcula el RiskScore y los AttackPaths de un host en base a su telemetría.
func AnalyzeHost(h *reporter.HostSummary) {
	var maxCVSS float64 = 0.0
	var contextMulti float64 = 1.0
	var fpMulti float64 = 1.0

	tagsMap := make(map[string]bool)

	// 1. Extraer el CVSS y metadatos del hallazgo más crítico
	for _, f := range h.StaticFindings {
		if f.CVSSBase > maxCVSS {
			maxCVSS = f.CVSSBase
			
			ctx := strings.ToLower(f.Context)
			if ctx == "external" || ctx == "both" {
				contextMulti = 1.2
			} else if ctx == "internal" {
				contextMulti = 0.8
			} else {
				contextMulti = 1.0
			}

			conf := strings.ToLower(f.Confidence)
			if conf == "confirmed" {
				fpMulti = 1.2
			} else if conf == "high" {
				fpMulti = 1.1
			} else if conf == "low" {
				fpMulti = 0.8
			} else {
				fpMulti = 1.0
			}
		}

		for _, t := range f.Tags {
			tagsMap[strings.ToLower(t)] = true
		}
	}

	// Analizar CVEs de los puertos
	for _, p := range h.Ports {
		for _, cve := range p.CVEs {
			sev := strings.ToLower(cve.Severity)
			if strings.Contains(sev, "crit") && maxCVSS < 9.0 {
				maxCVSS = 9.8
			} else if strings.Contains(sev, "high") && maxCVSS < 7.0 {
				maxCVSS = 7.5
			}
		}
		// Inferencia de tags por puertos
		if p.Port == 80 || p.Port == 443 || p.Port == 8080 || p.Port == 8443 {
			tagsMap["web"] = true
		}
		if p.Port == 3389 || p.Port == 22 || p.Port == 445 || p.Port == 139 {
			tagsMap["exposure"] = true
		}
	}

	// Cálculo matemático estricto (0-100)
	baseScore := maxCVSS * 10.0
	finalScore := baseScore * contextMulti * fpMulti
	h.RiskScore = math.Round(math.Min(finalScore, 100.0)*100) / 100

	// 2. Kill Chains basadas en Tags
	var paths []string
	isExposed := tagsMap["exposure"] || tagsMap["web"] || tagsMap["baseline"]

	if isExposed {
		if tagsMap["rce"] {
			paths = append(paths, "[External Web Surface] ➔ [Remote Code Execution]")
		}
		if tagsMap["ransomware"] {
			paths = append(paths, "[Initial Access] ➔ [Ransomware Deployment]")
		}
		if tagsMap["database"] || tagsMap["db"] || tagsMap["storage"] {
			paths = append(paths, "[Initial Access] ➔ [Data Breach (DB Exposed)]")
		}
		if tagsMap["auth-bypass"] || tagsMap["default-creds"] {
			paths = append(paths, "[Authentication Bypass] ➔ [Account Takeover]")
		}
		if tagsMap["smb"] || tagsMap["lateral-movement"] {
			paths = append(paths, "[Initial Access] ➔ [Lateral Movement via SMB]")
		}
		if tagsMap["cve"] && (tagsMap["exposure"] || tagsMap["web"]) {
			paths = append(paths, "[Public Exposure] ➔ [Exploitation of Known Vulnerability]")
		}
	}

	h.AttackPaths = paths
}
