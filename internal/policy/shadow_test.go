package policy

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nocktechnologies/nockguard/internal/audit"
)

func TestProposeShadowFromAuditDistinctAllowedTools(t *testing.T) {
	path := writeAuditTrail(t, []audit.Event{
		{Agent: "kit", Tool: "Read", Decision: "allow"},
		{Agent: "kit", Tool: "Read", Decision: "allow"},
		{Agent: "kit", Tool: "Bash", Decision: "deny"},
		{Agent: "kit", Tool: "nockcc_nock_list", Decision: "allow"},
		{Agent: "ash", Tool: "Write", Decision: "allow"},
	})

	got, err := ProposeShadowFromAudit("kit", path)
	if err != nil {
		t.Fatalf("ProposeShadowFromAudit: %v", err)
	}
	want := []string{"Read", "nockcc_nock_list"}
	if !reflect.DeepEqual(got.Tools, want) {
		t.Fatalf("proposal = %v, want %v", got, want)
	}
}

func TestShadowReportCountsWouldDeny(t *testing.T) {
	path := writeAuditTrail(t, []audit.Event{
		{Agent: "kit", Tool: "Read", Decision: "allow"},
		{Agent: "kit", Tool: "Bash", Decision: "would-deny"},
		{Agent: "kit", Tool: "Bash", Decision: "would-deny"},
		{Agent: "kit", Tool: "Write", Decision: "would-deny"},
		{Agent: "ash", Tool: "Bash", Decision: "would-deny"},
	})

	got, err := ShadowReportFromAudit("kit", path)
	if err != nil {
		t.Fatalf("ShadowReportFromAudit: %v", err)
	}
	want := []ShadowMiss{{Tool: "Bash", Count: 2}, {Tool: "Write", Count: 1}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("shadow report = %+v, want %+v", got, want)
	}
}

func writeAuditTrail(t *testing.T, events []audit.Event) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(AgentPubKeyEnvName("kit"), hex.EncodeToString(pub))
	a, err := audit.New(path, audit.WithEd25519Key(priv))
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	for _, ev := range events {
		if err := a.Record(ev); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

func TestProposeShadowFromAuditSkipsPatterns(t *testing.T) {
	path := writeAuditTrail(t, []audit.Event{
		{Agent: "kit", Tool: "*", Decision: "allow"},
		{Agent: "kit", Tool: "mcp__*", Decision: "allow"},
		{Agent: "kit", Tool: "read?", Decision: "allow"},
		{Agent: "kit", Tool: "[ab]", Decision: "allow"},
		{Agent: "kit", Tool: "Read", Decision: "allow"},
	})
	got, err := ProposeShadowFromAudit("kit", path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Tools, []string{"Read"}) || !reflect.DeepEqual(got.Skipped, []string{"*", "[ab]", "mcp__*", "read?"}) {
		t.Fatalf("proposal = %+v", got)
	}
}

func TestProposeShadowFromAuditRefusesUnverifiable(t *testing.T) {
	for _, kind := range []string{"unsigned", "tampered", "missing-key", "wrong-key", "missing-checkpoint", "empty"} {
		t.Run(kind, func(t *testing.T) {
			path := writeAuditTrail(t, []audit.Event{{Agent: "kit", Tool: "Read", Decision: "allow"}})
			switch kind {
			case "unsigned":
				if err := os.WriteFile(path, []byte(`{"agent":"kit","tool":"Read","decision":"allow"}`+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "tampered":
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(strings.ReplaceAll(string(data), "Read", "Write")), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-key":
				t.Setenv("HOME", t.TempDir())
				t.Setenv(AgentPubKeyEnvName("kit"), "")
			case "wrong-key":
				pub, _, err := ed25519.GenerateKey(nil)
				if err != nil {
					t.Fatal(err)
				}
				t.Setenv(AgentPubKeyEnvName("kit"), hex.EncodeToString(pub))
			case "missing-checkpoint":
				if err := os.Remove(path + ".hwm"); err != nil {
					t.Fatal(err)
				}
			case "empty":
				if err := os.WriteFile(path, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := ProposeShadowFromAudit("kit", path); err == nil {
				t.Fatal("unverifiable trail accepted")
			}
		})
	}
}
