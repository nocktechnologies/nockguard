package policy

import (
	"path/filepath"
	"reflect"
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
	if !reflect.DeepEqual(got, want) {
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
	a, err := audit.New(path)
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
