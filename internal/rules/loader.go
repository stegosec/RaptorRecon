package rules

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ──────────────────────────────────────────────
// Loader: carga y valida archivos YAML de reglas
// ──────────────────────────────────────────────

// LoadFile carga un único archivo de reglas y lo valida.
func LoadFile(path string) (*RuleSet, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("no se pudo abrir %q: %w", path, err)
	}
	defer f.Close()

	// Proteger contra YAML bombs leyendo un máximo de 1MB por archivo
	lr := io.LimitReader(f, 1024*1024)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("error leyendo %q: %w", path, err)
	}

	return parseBytes(data)
}

// LoadDir carga todos los archivos .yaml de un directorio y los combina.
// Los errores de archivos individuales se acumulan pero no detienen la carga.
func LoadDir(dir string) (*RuleSet, []error) {
	combined := &RuleSet{Name: "combined", Version: "1.0"}
	entries, err := os.ReadDir(dir)
	if err != nil {
		// Fallback: intentar buscar junto al binario ejecutable
		exe, exerr := os.Executable()
		if exerr == nil {
			altDir := filepath.Join(filepath.Dir(exe), dir)
			if altEntries, altErr := os.ReadDir(altDir); altErr == nil {
				dir = altDir
				entries = altEntries
				err = nil
			}
		}
		
		if err != nil {
			return combined, []error{fmt.Errorf("no se pudo leer directorio %q: %w", dir, err)}
		}
	}

	var errs []error

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		rs, err := LoadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		combined.Rules = append(combined.Rules, rs.Rules...)
	}
	return combined, errs
}

// parseBytes deserializa y valida un documento YAML.
func parseBytes(data []byte) (*RuleSet, error) {
	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("YAML inválido: %w", err)
	}
	if err := validateRuleSet(&rs); err != nil {
		return nil, err
	}
	// Aplicar defaults
	for i := range rs.Rules {
		applyDefaults(&rs.Rules[i])
	}
	return &rs, nil
}

// validateRuleSet comprueba que las reglas tienen los campos obligatorios.
func validateRuleSet(rs *RuleSet) error {
	seen := map[string]struct{}{}
	for i, r := range rs.Rules {
		if r.ID == "" {
			return fmt.Errorf("regla[%d]: campo 'id' obligatorio", i)
		}
		if _, dup := seen[r.ID]; dup {
			return fmt.Errorf("regla duplicada con id %q", r.ID)
		}
		seen[r.ID] = struct{}{}
		if r.Name == "" {
			return fmt.Errorf("regla %q: campo 'name' obligatorio", r.ID)
		}
	}
	return nil
}

// applyDefaults rellena campos opcionales con valores seguros.
func applyDefaults(r *Rule) {
	if r.Severity == "" {
		r.Severity = SeverityInfo
	}
	if r.Match.Logic == "" {
		r.Match.Logic = LogicOr
	}
}

// ──────────────────────────────────────────────
// Engine: evalúa reglas contra resultados de escaneo
// ──────────────────────────────────────────────

// ScanTarget contiene la información de un host+puerto para evaluar las reglas.
type ScanTarget struct {
	Host    string
	Port    int
	Service string
	Banner  string
}

// Evaluate aplica todas las reglas del RuleSet sobre un ScanTarget.
// Devuelve los Findings que coincidan.
func Evaluate(rs *RuleSet, t ScanTarget) []Finding {
	var findings []Finding
	for _, rule := range rs.Rules {
		if f, ok := matchRule(rule, t); ok {
			findings = append(findings, f)
		}
	}
	return findings
}

// matchRule evalúa una sola regla contra un target.
func matchRule(r Rule, t ScanTarget) (Finding, bool) {
	m := r.Match
	portMatch := matchPort(m.Ports, t.Port)
	serviceMatch := matchAny(m.Services, strings.ToLower(t.Service))
	bannerMatch, bannerHit := matchBanner(m.Banners, t.Banner)

	var hit bool
	var matchedOn string

	if m.Logic == LogicAnd {
		// Sólo evaluar condiciones que estén definidas en la regla
		conditions := make([]bool, 0, 3)
		var labels []string
		if len(m.Ports) > 0 {
			conditions = append(conditions, portMatch)
			labels = append(labels, fmt.Sprintf("port:%d", t.Port))
		}
		if len(m.Services) > 0 {
			conditions = append(conditions, serviceMatch)
			labels = append(labels, "service:"+t.Service)
		}
		if len(m.Banners) > 0 {
			conditions = append(conditions, bannerMatch)
			labels = append(labels, "banner:"+bannerHit)
		}
		hit = allTrue(conditions)
		if hit {
			matchedOn = strings.Join(labels, " AND ")
		}
	} else { // LogicOr (default)
		switch {
		case portMatch && len(m.Ports) > 0:
			hit = true
			matchedOn = fmt.Sprintf("port:%d", t.Port)
		case serviceMatch && len(m.Services) > 0:
			hit = true
			matchedOn = "service:" + t.Service
		case bannerMatch && len(m.Banners) > 0:
			hit = true
			matchedOn = "banner:" + bannerHit
		}
	}

	if !hit {
		return Finding{}, false
	}

	return Finding{
		RuleID:            r.ID,
		RuleName:          r.Name,
		Severity:          r.Severity,
		Context:           r.Context,
		Confidence:        r.Confidence,
		CVSSBase:          r.CVSSBase,
		Tags:              r.Tags,
		Host:              t.Host,
		Port:              t.Port,
		Service:           t.Service,
		MatchedOn:         matchedOn,
		Remediation:       r.Remediation,
		References:        r.References,
		Mitre:             r.Mitre,
		Compliance:        r.Compliance,
		SLA:               r.SLA,
	}, true
}

// ──────────────────────────────────────────────
// Helpers de matching
// ──────────────────────────────────────────────

func matchPort(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

func matchAny(patterns []string, value string) bool {
	for _, p := range patterns {
		if strings.EqualFold(p, value) {
			return true
		}
	}
	return false
}

func matchBanner(patterns []string, banner string) (bool, string) {
	lower := strings.ToLower(banner)
	for _, p := range patterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true, p
		}
	}
	return false, ""
}

func allTrue(bs []bool) bool {
	for _, b := range bs {
		if !b {
			return false
		}
	}
	return len(bs) > 0
}
