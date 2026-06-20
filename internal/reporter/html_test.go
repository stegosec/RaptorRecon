package reporter

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/raptor-recon/raptor/internal/rules"
	"github.com/raptor-recon/raptor/internal/scanner"
)

func TestWriteHTMLReport(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "raptor-test-*")
	if err != nil {
		t.Fatalf("No se pudo crear directorio temporal: %v", err)
	}
	defer os.RemoveAll(tempDir)

	reportPath := filepath.Join(tempDir, "report.html")

	subnets := []SubnetSummary{
		{
			CIDR: "192.168.1.0/24",
			Hosts: []HostSummary{
				{
					IP: "192.168.1.1",
					OS: "Linux/Unix",
					Ports: []PortSummary{
						{Result: scanner.Result{Host: "192.168.1.1", Port: 80, Open: true, Latency: 10 * time.Millisecond, Banner: "HTTP/1.1 200 OK"}},
						{Result: scanner.Result{Host: "192.168.1.1", Port: 443, Open: true, Latency: 12 * time.Millisecond}},
					},
					StaticFindings: []rules.Finding{
						{
							RuleID:      "RR-001",
							RuleName:    "HTTP Open",
							Severity:    rules.SeverityInfo,
							Host:        "192.168.1.1",
							Port:        80,
							Service:     "http",
							MatchedOn:   "port:80",
							Remediation: "Desactivar HTTP si no es necesario.",
							References:  []string{"https://example.com"},
						},
						{
							RuleID:      "RR-002",
							RuleName:    "SSL Expired",
							Severity:    rules.SeverityHigh,
							Host:        "192.168.1.1",
							Port:        443,
							Service:     "https",
							MatchedOn:   "banner:expired",
							Remediation: "Renovar certificado SSL.",
						},
					},
				},
			},
		},
	}

	f, err := os.Create(reportPath)
	if err != nil {
		t.Fatalf("No se pudo crear archivo de prueba: %v", err)
	}
	err = WriteHTMLReport(f, "192.168.1.1", "0.1.0", subnets, "", nil)
	f.Close()
	if err != nil {
		t.Fatalf("Error escribiendo reporte HTML: %v", err)
	}

	// Verificar existencia
	if _, err := os.Stat(reportPath); os.IsNotExist(err) {
		t.Fatalf("El archivo de reporte no fue creado")
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("No se pudo leer el archivo de reporte: %v", err)
	}

	if len(data) == 0 {
		t.Errorf("El archivo de reporte está vacío")
	}
}
