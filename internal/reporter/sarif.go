package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/raptor-recon/raptor/internal/rules"
)

// SarifLog es el nodo raíz de un documento SARIF.
type SarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SarifRun `json:"runs"`
}

// SarifRun representa una invocación de la herramienta de análisis.
type SarifRun struct {
	Tool       SarifTool              `json:"tool"`
	Results    []SarifResult          `json:"results"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SarifTool describe la herramienta (Raptor Recon).
type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SarifRule `json:"rules"`
}

// SarifRule describe un tipo de hallazgo.
type SarifRule struct {
	Id               string                 `json:"id"`
	Name             string                 `json:"name"`
	ShortDescription SarifMessage           `json:"shortDescription"`
	Help             SarifMessage           `json:"help,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

// SarifResult es un finding específico.
type SarifResult struct {
	RuleId     string                 `json:"ruleId"`
	Level      string                 `json:"level"`
	Message    SarifMessage           `json:"message"`
	Locations  []SarifLocation        `json:"locations"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type SarifMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           SarifRegion           `json:"region,omitempty"`
}

type SarifArtifactLocation struct {
	Uri string `json:"uri"`
}

type SarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

// mapSeverity SARIF levels: "error", "warning", "note", "none"
func mapSeverity(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical, rules.SeverityHigh:
		return "error"
	case rules.SeverityMedium, rules.SeverityLow:
		return "warning"
	default:
		return "note"
	}
}

// ExportToSARIF exporta la lista de findings a formato OASIS SARIF v2.1.0, preservando metadatos tácticos.
// pivotSummary contiene los hallazgos de pivot para incluir como resultados separados (nil = sin pivot).
func ExportToSARIF(hosts []HostSummary, outputPath string, version string, pivotSummary []PivotSummaryEntry) error {
	run := SarifRun{
		Tool: SarifTool{
			Driver: SarifDriver{
				Name:    "Raptor Recon",
				Version: version,
				Rules:   []SarifRule{},
			},
		},
		Results:    []SarifResult{},
		Properties: make(map[string]interface{}),
	}

	ruleMap := make(map[string]bool)
	allAttackPaths := []string{}

	// Registrar la regla estática PIVOT-EXPOSURE si hay findings de pivot
	if len(pivotSummary) > 0 {
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, SarifRule{
			Id:   "PIVOT-EXPOSURE",
			Name: "Proxy Pivot Exposure",
			ShortDescription: SarifMessage{
				Text: "Servicio solo accesible vía proxy — invisible al escaneo directo",
			},
			Help: SarifMessage{
				Text: "Un servicio detectado únicamente a través de un proxy HTTP CONNECT o SOCKS5 " +
					"indica una configuración de firewall asimétrica o binding en loopback. " +
					"El proxy actúa como vector de acceso no autorizado a servicios internos.",
			},
			Properties: map[string]interface{}{
				"tags":     []string{"pivot", "proxy", "firewall-bypass", "network-exposure"},
				"severity": "critical",
			},
		})
		ruleMap["PIVOT-EXPOSURE"] = true
		ruleMap["PIVOT-SUBNET-EXPOSURE"] = true
		ruleMap["PIVOT-RANGE-EXPOSURE"] = true

		// Emitir resultados SARIF por cada finding de pivot
		for _, entry := range pivotSummary {
			for _, f := range entry.Findings {
				level := "error" // pivot-only siempre es error
				if f.Visibility == "both" {
					level = "warning"
				}
				msgText := fmt.Sprintf(
					"Puerto %d/%s en %s %s vía proxy %s:%d (%s). Vector: HTTP CONNECT / SOCKS5 Tunneling.",
					f.Port, f.Protocol, f.Host,
					pivotVisibilityLabel(f.Visibility),
					entry.ProxyHost, entry.ProxyPort, entry.ProxyType,
				)
				res := SarifResult{
					RuleId: "PIVOT-EXPOSURE",
					Level:  level,
					Message: SarifMessage{
						Text:     msgText,
						Markdown: msgText + fmt.Sprintf("\n\n**Proxy Vector:** `%s:%d` (%s)\n\n**Visibilidad:** `%s`", entry.ProxyHost, entry.ProxyPort, entry.ProxyType, f.Visibility),
					},
					Locations: []SarifLocation{
						{
							PhysicalLocation: SarifPhysicalLocation{
								ArtifactLocation: SarifArtifactLocation{
									Uri: fmt.Sprintf("tcp://%s:%d", f.Host, f.Port),
								},
								Region: SarifRegion{StartLine: 1, StartColumn: 1},
							},
						},
					},
					Properties: map[string]interface{}{
						"proxyHost":  entry.ProxyHost,
						"proxyPort":  entry.ProxyPort,
						"proxyType":  entry.ProxyType,
						"visibility": f.Visibility,
						"pivotLevel": pivotLevelFromContext(f.Context),
					},
				}
				run.Results = append(run.Results, res)
			}
		}
	}

	for _, host := range hosts {
		if host.AttackPaths != nil && len(host.AttackPaths) > 0 {
			for _, path := range host.AttackPaths {
				allAttackPaths = append(allAttackPaths, fmt.Sprintf("%s: %s", host.IP, path))
			}
		}

		for _, f := range host.StaticFindings {
			// Construir reglas únicas dinámicamente
			if !ruleMap[f.RuleID] {
				ruleMap[f.RuleID] = true
				rule := SarifRule{
					Id:   f.RuleID,
					Name: f.RuleName,
					ShortDescription: SarifMessage{
						Text: f.RuleName,
					},
					Help: SarifMessage{
						Text: fmt.Sprintf("Description: %s\n\nRemediation: %s", f.Description, f.Remediation),
					},
					Properties: map[string]interface{}{
						"tags":       f.Tags,
						"mitre":      f.Mitre,
						"compliance": f.Compliance,
						"severity":   string(f.Severity),
					},
				}
				run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
			}

			// Inyectar Evidence y SLA en Markdown
			msgText := fmt.Sprintf("El host %s en el puerto %d presenta vulnerabilidad: %s. %s", f.Host, f.Port, f.RuleName, f.Description)
			msgMarkdown := msgText
			if f.SLA != "" {
				msgMarkdown += fmt.Sprintf("\n\n**SLA de Remediación:** %s", f.SLA)
			}
			if f.Evidence != "" {
				msgMarkdown += fmt.Sprintf("\n\n**Evidencia (PoC):**\n```text\n%s\n```", f.Evidence)
			}

			// Construir Resultado
			res := SarifResult{
				RuleId: f.RuleID,
				Level:  mapSeverity(f.Severity),
				Message: SarifMessage{
					Text:     msgText,
					Markdown: msgMarkdown,
				},
				Locations: []SarifLocation{
					{
						PhysicalLocation: SarifPhysicalLocation{
							ArtifactLocation: SarifArtifactLocation{
								Uri: fmt.Sprintf("tcp://%s:%d", f.Host, f.Port),
							},
							Region: SarifRegion{
								StartLine: 1, StartColumn: 1,
							},
						},
					},
				},
				Properties: map[string]interface{}{
					"riskScore":  host.RiskScore,
					"confidence": f.Confidence,
					"context":    f.Context,
					"cvssBase":   f.CVSSBase,
				},
			}
			run.Results = append(run.Results, res)
		}
	}

	if len(allAttackPaths) > 0 {
		run.Properties["attackPaths"] = allAttackPaths
	}

	logReport := SarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs:    []SarifRun{run},
	}

	cleanPath := filepath.Clean(outputPath)
	tmpPath := filepath.Clean(cleanPath + ".tmp")
	file, err := os.Create(tmpPath) // #nosec G304 -- User supplied output path via CLI
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(logReport)

	if closeErr := file.Close(); closeErr != nil && err == nil {
		err = closeErr
	}

	if err != nil {
		return err
	}

	return os.Rename(tmpPath, cleanPath)
}

// pivotVisibilityLabel retorna texto descriptivo para el SARIF message.
func pivotVisibilityLabel(v string) string {
	if v == "pivot-only" {
		return "SOLO accesible"
	}
	return "también accesible"
}

// pivotLevelFromContext extrae el nivel de pivot (L1/L2/L3) del campo Context del finding.
func pivotLevelFromContext(ctx string) string {
	if len(ctx) >= 8 {
		switch ctx[6:8] {
		case "L1":
			return "L1-SameIP"
		case "L2":
			return "L2-Subnet"
		case "L3":
			return "L3-Range"
		}
	}
	return "L1-SameIP"
}

