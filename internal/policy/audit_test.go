package policy

import (
	"path/filepath"
	"testing"
)

func TestAuditorDisabledWhenAbsent(t *testing.T) {
	path := writePolicy(t, `
agents:
  kit:
    allow: ["*"]
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := eng.Auditor()
	if err != nil {
		t.Fatalf("Auditor: %v", err)
	}
	defer a.Close()
	if a.Enabled() {
		t.Error("no audit block should yield a disabled auditor")
	}
}

func TestAuditorDisabledWhenEnabledFalse(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	path := writePolicy(t, `
audit:
  enabled: false
  path: `+auditPath+`
agents:
  kit:
    allow: ["*"]
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := eng.Auditor()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if a.Enabled() {
		t.Error("audit.enabled=false should yield a disabled auditor even with a path")
	}
}

func TestAuditorEnabledWithPath(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	path := writePolicy(t, `
audit:
  enabled: true
  path: `+auditPath+`
agents:
  kit:
    allow: ["*"]
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := eng.Auditor()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if !a.Enabled() {
		t.Fatal("audit.enabled=true with a path should enable the auditor")
	}
}
