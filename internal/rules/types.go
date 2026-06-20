// Package rules implementa el motor de reglas YAML de Raptor Recon.
// Las reglas son la única forma de inyectar lógica de detección sin recompilar el binario.
package rules

// ──────────────────────────────────────────────
// Estructura del archivo YAML de reglas
// ──────────────────────────────────────────────

// RuleSet es el documento raíz de un archivo .yaml de reglas.
type RuleSet struct {
	Version  string `yaml:"version"`   // semver de esquema, e.g. "1.0"
	Name     string `yaml:"name"`      // nombre del conjunto
	Author   string `yaml:"author"`
	Rules    []Rule `yaml:"rules"`
}

// Rule define una condición de detección y su metadata.
type Rule struct {
	ID          string      `yaml:"id"`          // identificador único, e.g. "RR-001"
	Name        string      `yaml:"name"`        // nombre legible
	Description string      `yaml:"description"`
	Severity          Severity    `yaml:"severity"`    // critical | high | medium | low | info
	Context           string      `yaml:"context,omitempty"`
	Confidence        string      `yaml:"confidence,omitempty"` // low | medium | high | confirmed
	CVSSBase          float64     `yaml:"cvss_base,omitempty"`
	Tags              []string    `yaml:"tags"`        // e.g. ["cve", "default-creds", "exposure"]
	Match             MatchBlock  `yaml:"match"`
	Remediation       string      `yaml:"remediation"`
	References        []string    `yaml:"references"`  // URLs a CVE, NIST, etc.
	Mitre       []string    `yaml:"mitre"`       // Mapeo MITRE ATT&CK
	Compliance  []string    `yaml:"compliance"`  // Mapeo a normativas (PCI, SOC2, etc)
	SLA         string      `yaml:"sla"`         // SLA de remediación esperado
}

// MatchBlock contiene todas las condiciones de una regla.
// Logic controla si se evalúan con AND u OR.
type MatchBlock struct {
	Logic      Logic       `yaml:"logic"`               // "or" (default) | "and"
	Ports      []int       `yaml:"ports"`               // puertos a verificar
	Services   []string    `yaml:"services,omitempty"`  // nombres de servicio (ssh, http…)
	Banners    []string    `yaml:"banners"`             // substrings a buscar en el banner
	OSHints    []string    `yaml:"os_hints"`            // substrings en TTL/banner que indican OS
	HTTPPaths  []string    `yaml:"http_paths,omitempty"`
	Conditions interface{} `yaml:"conditions,omitempty"`
}

// ──────────────────────────────────────────────
// Tipos enumerados
// ──────────────────────────────────────────────

// Severity representa el nivel de criticidad de una regla.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Logic determina cómo se combinan las condiciones de un MatchBlock.
type Logic string

const (
	LogicOr  Logic = "or"  // basta con que UNA condición sea verdadera
	LogicAnd Logic = "and" // TODAS las condiciones deben ser verdaderas
)

// ──────────────────────────────────────────────
// Resultado de aplicar una regla
// ──────────────────────────────────────────────

// Finding representa una coincidencia de regla sobre un host/puerto.
type Finding struct {
	RuleID            string   `json:"rule_id"`
	RuleName          string   `json:"rule_name"`
	Severity          Severity `json:"severity"`
	Context           string   `json:"context,omitempty"`
	Confidence        string   `json:"confidence,omitempty"`
	CVSSBase          float64  `json:"cvss_base,omitempty"`
	Tags              []string `json:"tags,omitempty"`
	Host              string   `json:"host"`
	Port        int      `json:"port"`
	Service     string   `json:"service"`
	MatchedOn   string   `json:"matched_on"` // descripción de qué condición disparó la regla
	Description string   `json:"description,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`
	Mitre       []string `json:"mitre,omitempty"`      // Mapeo MITRE ATT&CK
	Compliance  []string `json:"compliance,omitempty"` // Mapeo de Compliance
	SLA         string   `json:"sla,omitempty"`        // SLA para remediación
	Evidence    string   `json:"evidence,omitempty"`   // Prueba cruda del hallazgo (PoC)
}
