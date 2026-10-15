package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nockguard/internal/audit"
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

func TestActionPairingRequiresDurableAuditAndDefaultsOff(t *testing.T) {
	path := writePolicy(t, `
agents:
  kit:
    allow: ["*"]
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if eng.ActionPairingEnabled() {
		t.Fatal("action pairing must default off")
	}

	path = writePolicy(t, `
audit:
  enabled: false
  action_pairing: true
agents:
  kit:
    allow: ["*"]
`)
	if _, err := Load(path); err == nil {
		t.Fatal("action_pairing without enabled required audit was accepted")
	}

	path = writePolicy(t, `
audit:
  enabled: true
  action_pairing: true
agents:
  kit:
    allow: ["*"]
`)
	eng, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !eng.ActionPairingEnabled() {
		t.Fatal("explicit enabled action_pairing should be available")
	}
}

func TestAuditorResumesUnsignedRunSequenceWhenActionPairingIsEnabled(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	runID := "00112233445566778899aabbccddeeff"
	seed, err := audit.New(auditPath, audit.WithActionPairing())
	if err != nil {
		t.Fatal(err)
	}
	first := audit.Event{Agent: "kit", Tool: "read_file", Decision: "allow", SchemaVersion: 2, RecordType: "decision", RunID: runID, ActionID: runID + ".1"}
	if err := seed.RecordRequired(first); err != nil {
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}

	path := writePolicy(t, `
audit:
  enabled: true
  action_pairing: true
  path: `+auditPath+`
agents:
  kit:
    allow: ["*"]
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := eng.Auditor()
	if err != nil {
		t.Fatal(err)
	}
	second := audit.Event{Agent: "kit", Tool: "read_file", Decision: "allow", SchemaVersion: 2, RecordType: "decision", RunID: runID, ActionID: runID + ".2"}
	if err := writer.RecordRequired(second); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit rows = %d, want 2", len(lines))
	}
	for i, line := range lines {
		var row struct {
			RunSeq uint64 `json:"run_seq"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		if want := uint64(i + 1); row.RunSeq != want {
			t.Fatalf("row %d run_seq=%d, want %d", i, row.RunSeq, want)
		}
	}
}
