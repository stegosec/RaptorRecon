package reporter

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io"
	"time"

	"github.com/raptor-recon/raptor/internal/enrichment"
	"github.com/raptor-recon/raptor/internal/rules"
	"github.com/raptor-recon/raptor/internal/scanner"
)

//go:embed templates/* templates/libs/*
var templatesFS embed.FS

// PortSummary agrupa el resultado de un puerto con sus vulnerabilidades (CVEs).
type PortSummary struct {
	scanner.Result
	CVEs []enrichment.CVE `json:"cves,omitempty"`
}

// HostSummary groups all results for a single IP.
type HostSummary struct {
	IP             string               `json:"ip"`
	Hostname       string               `json:"hostname,omitempty"`
	MACAddress     string               `json:"mac_address,omitempty"`
	Vendor         string               `json:"vendor,omitempty"`
	OS             string               `json:"os,omitempty"`
	Ports          []PortSummary        `json:"ports,omitempty"`
	StaticFindings []rules.Finding      `json:"static_findings,omitempty"`
	RiskScore      float64              `json:"risk_score"`
	AttackPaths    []string             `json:"attack_paths,omitempty"`
	TLSDomains     []string             `json:"tls_domains,omitempty"`
	PivotFindings  []PivotFindingEntry  `json:"pivot_findings,omitempty"` // Hallazgos obtenidos vía proxy pivot
}

// SubnetSummary agrupa hosts que pertenecen a un mismo bloque de red (/24 lógico).
type SubnetSummary struct {
	CIDR  string        `json:"cidr"`
	Hosts []HostSummary `json:"hosts"`
}

// ──────────────────────────────────────────────
// Tipos de Pivot (sin importar el paquete pivot para evitar ciclos)
// ──────────────────────────────────────────────

// PivotFindingEntry representa un hallazgo obtenido a través de pivot.
// Definido en reporter para evitar dependencia cíclica con el paquete pivot.
type PivotFindingEntry struct {
	Host        string         `json:"host"`
	Port        int            `json:"port"`
	Protocol    string         `json:"protocol"`
	Severity    rules.Severity `json:"severity"`
	RuleID      string         `json:"rule_id"`
	RuleName    string         `json:"rule_name"`
	Description string         `json:"description"`
	Context     string         `json:"context"`
	ProxyHost   string         `json:"proxy_host"`
	ProxyPort   int            `json:"proxy_port"`
	ProxyType   string         `json:"proxy_type"`   // "http-connect" | "socks5"
	Visibility  string         `json:"visibility"`   // "pivot-only" | "both"
}

// PivotSummaryEntry agrupa los hallazgos de pivot para un proxy específico.
type PivotSummaryEntry struct {
	ProxyHost string             `json:"proxy_host"`
	ProxyPort int                `json:"proxy_port"`
	ProxyType string             `json:"proxy_type"`
	Findings  []PivotFindingEntry `json:"findings"`
}


// HTMLReportData contiene los datos necesarios para renderizar el reporte HTML.
type HTMLReportData struct {
	Target        string
	Timestamp     string
	Version       string
	CSS           template.CSS
	JS            template.JS
	ChartJSBase64 string
	VisJSBase64   string
	DataB64       string
	DeltaB64      string
	PivotB64      string // JSON base64 de []PivotSummaryEntry para renderizado en JS
}

// RaptorData es la estructura que se inyecta como JSON.
type RaptorData struct {
	Target       string               `json:"target"`
	Subnets      []SubnetSummary      `json:"subnets"`
	PivotSummary []PivotSummaryEntry  `json:"pivot_findings,omitempty"`
}

// WriteHTMLReport genera el reporte HTML de forma segura usando subtemplates (ParseFS).
// Recibe un io.Writer para prevenir vulnerabilidades de path traversal (G304).
// pivotSummary contiene los hallazgos de pivot para incluir en el reporte (nil = sin pivot).
func WriteHTMLReport(w io.Writer, target string, version string, subnets []SubnetSummary, deltaB64 string, pivotSummary []PivotSummaryEntry) error {
	// 1. Parsear TODOS los archivos embebidos desde FS.
	// Esto permite que report.html llame a {{template "style.css"}} nativamente.
	tmpl, err := template.ParseFS(templatesFS, "templates/report.html", "templates/style.css", "templates/script.js")
	if err != nil {
		return err
	}

	chartJSData, err := templatesFS.ReadFile("templates/libs/chart.min.js")
	if err != nil {
		return err
	}
	visJSData, err := templatesFS.ReadFile("templates/libs/vis-network.min.js")
	if err != nil {
		return err
	}

	// 3. Construir datos del reporte
	raptorData := RaptorData{
		Target:       target,
		Subnets:      subnets,
		PivotSummary: pivotSummary,
	}
	jsonData, _ := json.Marshal(raptorData)

	// Codificar pivot summary por separado para renderizado independiente en JS
	var pivotB64 string
	if len(pivotSummary) > 0 {
		if pivotJSON, err := json.Marshal(pivotSummary); err == nil {
			pivotB64 = base64.StdEncoding.EncodeToString(pivotJSON)
		}
	}

	data := HTMLReportData{
		Target:        target,
		Timestamp:     time.Now().Format("2006-01-02 15:04:05 UTC"),
		Version:       version,
		ChartJSBase64: base64.StdEncoding.EncodeToString(chartJSData),
		VisJSBase64:   base64.StdEncoding.EncodeToString(visJSData),
		DataB64:       base64.StdEncoding.EncodeToString(jsonData),
		DeltaB64:      deltaB64,
		PivotB64:      pivotB64,
	}

	// 4. Renderizar directamente al Writer
	return tmpl.Execute(w, data)
}
