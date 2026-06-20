package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDir(t *testing.T) {
	tmpdir := t.TempDir()
	
	yamlContent := `
version: "1.0"
name: Test
author: test
rules:
  - id: TEST-01
    name: Test Rule
    severity: high
    match:
      ports: [80]
`
	filepath := filepath.Join(tmpdir, "test.yaml")
	if err := os.WriteFile(filepath, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	rs, errs := LoadDir(tmpdir)
	if len(errs) > 0 {
		t.Fatalf("expected 0 errors, got %d", len(errs))
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rs.Rules))
	}
	if rs.Rules[0].ID != "TEST-01" {
		t.Errorf("expected rule ID TEST-01, got %s", rs.Rules[0].ID)
	}
}

func TestEvaluate(t *testing.T) {
	rs := &RuleSet{
		Rules: []Rule{
			{
				ID: "TEST-01",
				Match: MatchBlock{
					Logic: LogicOr,
					Ports: []int{80},
				},
			},
		},
	}
	
	target := ScanTarget{Port: 80}
	findings := Evaluate(rs, target)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}
