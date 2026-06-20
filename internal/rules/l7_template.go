package rules

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// L7Template representa una regla de capa 7 interactiva basada en handshakes binarios.
type L7Template struct {
	ID          string    `yaml:"id"`
	Name        string    `yaml:"name"`
	Description string    `yaml:"description"`
	Severity    Severity  `yaml:"severity"`
	Protocol    string    `yaml:"protocol"` // tcp, udp
	Port        int       `yaml:"port"`     // Puerto objetivo
	Payloads    []string  `yaml:"payloads,omitempty"` // Cadenas hexadecimales a inyectar
	Matchers    []Matcher `yaml:"matchers"`
}

type MatcherType string

const (
	MatcherTypeRegex      MatcherType = "regex"       // Evaluación por expresión regular (texto plano)
	MatcherTypeHex        MatcherType = "hex"         // Evaluación binaria pura (bytes.Contains)
	MatcherTypeContains   MatcherType = "contains"    // Substring case-insensitive (texto plano)
	MatcherTypeStartsWith MatcherType = "starts_with" // Prefijo case-insensitive (handshakes fijos)
)

// Matcher define cómo se evaluará la respuesta cruda del socket.
type Matcher struct {
	Type  MatcherType `yaml:"type"`  // "regex" (solo para texto) o "hex" (para bytes puros)
	Value string      `yaml:"value"` // El patrón regex o la cadena hex esperada
}

// DecodeHex convierte un string hexadecimal en un array de bytes puro para enviar por sockets.
func DecodeHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// LoadL7Templates escanea un directorio y devuelve todos los templates válidos encontrados.
func LoadL7Templates(dir string) ([]L7Template, error) {
	var templates []L7Template
	entries, err := os.ReadDir(dir)
	if err != nil {
		// Fallback: buscar relativo al ejecutable
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
			return templates, fmt.Errorf("no se pudo leer el directorio de templates L7 %q: %v", dir, err)
		}
	}

	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}

		path := filepath.Join(dir, e.Name())
		data, readErr := os.ReadFile(path) // #nosec G304 - Filepath is safe, sourced from ReadDir
		if readErr != nil {
			continue
		}

		var tmpl L7Template
		if yamlErr := yaml.Unmarshal(data, &tmpl); yamlErr != nil {
			continue
		}
		
		if tmpl.Severity == "" {
			tmpl.Severity = SeverityInfo
		}

		templates = append(templates, tmpl)
	}

	return templates, nil
}
