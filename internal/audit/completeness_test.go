package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testRunID = "0123456789abcdef0123456789abcdef"

func TestRunLifecycleWriterAndAssessment(t *testing.T) {
	now := time.Date(2026, 10, 17, 6, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := New(path, WithSigningKey([]byte("test signing key")))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.clock = func() time.Time { return now }
	row := func(ev Event) {
		t.Helper()
		ev.Agent, ev.RunID, ev.SchemaVersion = "demo", testRunID, 2
		if err := a.RecordRequired(ev); err != nil {
			t.Fatal(err)
		}
	}
	read := func() []byte {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, count, err := VerifyWithCheckpoint(path, []byte("test signing key")); err != nil || count == 0 {
			t.Fatalf("integrity verification: count=%d err=%v", count, err)
		}
		return b
	}
	row(Event{RecordType: "run", RunEvent: "open"})
	if got := AssessRuns(read(), true, now)[0].Verdict; got != "IN_PROGRESS" {
		t.Fatalf("recent open = %s", got)
	}
	row(Event{RecordType: "decision", Tool: "read", Decision: "dispatch", ActionID: testRunID + ".1"})
	row(Event{RecordType: "run", RunEvent: "heartbeat"})
	row(Event{RecordType: "action_observation", Tool: "read", ActionID: testRunID + ".1", Observation: "outcome_unknown", Cause: "timeout"})
	row(Event{RecordType: "run", RunEvent: "close"})
	data := read()
	if got := AssessRuns(data, true, now)[0].Verdict; got != "LIMITED" {
		t.Fatalf("closed stream = %s", got)
	}
	if !strings.Contains(string(data), `"run_count":4`) || !strings.Contains(string(data), `"run_head":"`) {
		t.Fatalf("close must commit count and head: %s", data)
	}
	if err := a.RecordRequired(Event{Agent: "demo", SchemaVersion: 2, RecordType: "run", RunID: testRunID, RunEvent: "heartbeat"}); err == nil {
		t.Fatal("writer accepted a row after close")
	}
}

func TestRunAssessmentNegativeControls(t *testing.T) {
	now := time.Date(2026, 10, 17, 6, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, want string
		age        time.Duration
		future     bool
		close      bool
		pending    bool
	}{
		{"killed run has unknown end", "INCOMPLETE", -91 * time.Second, false, false, false},
		{"future heartbeat", "UNASSESSABLE", 31 * time.Second, true, false, false},
		{"closed dispatch missing observation", "INCOMPLETE", 0, false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			a, err := New(path, WithSigningKey([]byte("test signing key")))
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			a.clock = func() time.Time { return now.Add(tc.age) }
			if err := a.RecordRequired(Event{Agent: "demo", SchemaVersion: 2, RecordType: "run", RunID: testRunID, RunEvent: "open"}); err != nil {
				t.Fatal(err)
			}
			if tc.pending {
				if err := a.RecordRequired(Event{Agent: "demo", SchemaVersion: 2, RecordType: "decision", RunID: testRunID, ActionID: testRunID + ".1", Tool: "read", Decision: "dispatch"}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.close {
				if err := a.RecordRequired(Event{Agent: "demo", SchemaVersion: 2, RecordType: "run", RunID: testRunID, RunEvent: "close"}); err != nil {
					t.Fatal(err)
				}
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := AssessRuns(data, true, now)[0].Verdict; got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestRunAssessmentLegacyTruncationAndBrokenStructure(t *testing.T) {
	now := time.Now().UTC()
	if got := AssessRuns([]byte(`{"ts":"t","agent":"a","tool":"x","decision":"allow","sig":"x"}`+"\n"), true, now)[0].Verdict; got != "UNVERIFIED" {
		t.Fatalf("legacy = %s", got)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := New(path, WithSigningKey([]byte("test signing key")))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := a.RecordRequired(Event{Agent: "demo", SchemaVersion: 2, RecordType: "run", RunID: testRunID, RunEvent: "open"}); err != nil {
		t.Fatal(err)
	}
	if err := a.RecordRequired(Event{Agent: "demo", SchemaVersion: 2, RecordType: "run", RunID: testRunID, RunEvent: "close"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	// A cut tail cannot be promoted by the analyzer while its signed checkpoint
	// still commits the removed close row.
	cut := []byte(lines[0] + "\n")
	if _, _, err := VerifyWithCheckpointBytes(cut, mustRead(t, path+".hwm"), []byte("test signing key")); err == nil {
		t.Fatal("truncated trail passed integrity verification")
	}
	if got := AssessRuns(cut, false, now)[0].Verdict; got != "UNASSESSABLE" {
		t.Fatalf("truncated trail = %s", got)
	}
	// A signature-valid but structurally invalid stream is a broken run.
	if got := AssessRuns(append(data, []byte(lines[1]+"\n")...), true, now)[0].Verdict; got != "BROKEN" {
		t.Fatalf("row after close = %s", got)
	}
}

func TestInterleavedSignedRunsKeepIndependentHeads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	key := []byte("shared run signing key")
	first, err := New(path, WithSigningKey(key))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := New(path, WithSigningKey(key))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	otherID := "fedcba9876543210fedcba9876543210"
	for _, step := range []struct {
		a       *Auditor
		id, evt string
	}{
		{first, testRunID, "open"},
		{second, otherID, "open"},
		{first, testRunID, "heartbeat"},
		{second, otherID, "close"},
		{first, testRunID, "close"},
	} {
		if err := step.a.RecordRequired(Event{Agent: "demo", SchemaVersion: 2, RecordType: "run", RunID: step.id, RunEvent: step.evt}); err != nil {
			t.Fatal(err)
		}
	}
	rows, count, err := VerifyWithCheckpoint(path, key)
	if err != nil || rows != count {
		t.Fatalf("global trail: rows=%d checkpoint=%d err=%v", rows, count, err)
	}
	data := mustRead(t, path)
	for _, result := range AssessRuns(data, true, time.Now()) {
		if result.Verdict != "LIMITED" {
			t.Fatalf("interleaved run %+v", result)
		}
	}
}

func TestRunAssessmentActionlessDecisionAllowlist(t *testing.T) {
	now := time.Date(2026, 10, 17, 6, 0, 0, 0, time.UTC)
	for _, tc := range []struct{ decision, want string }{
		{"method-allow", "LIMITED"},
		{"method-deny", "LIMITED"},
		{"hide", "LIMITED"},
		{"deny", "BROKEN"},
		{"state-write", "BROKEN"},
		{"approval-granted", "BROKEN"},
	} {
		t.Run(tc.decision, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			a, err := New(path, WithSigningKey([]byte("test signing key")))
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			a.clock = func() time.Time { return now }
			for _, ev := range []Event{
				{RecordType: "run", RunEvent: "open"},
				{RecordType: "decision", Tool: "x", Decision: tc.decision},
				{RecordType: "run", RunEvent: "close"},
			} {
				ev.Agent, ev.RunID, ev.SchemaVersion = "demo", testRunID, 2
				if err := a.RecordRequired(ev); err != nil {
					t.Fatal(err)
				}
			}
			if got := AssessRuns(mustRead(t, path), true, now)[0].Verdict; got != tc.want {
				t.Fatalf("action-less %s = %s, want %s", tc.decision, got, tc.want)
			}
		})
	}
}

func TestRunWithoutOpenKeepsUnassessableVerdict(t *testing.T) {
	now := time.Date(2026, 10, 17, 6, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := New(path, WithSigningKey([]byte("test signing key")))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.clock = func() time.Time { return now }
	// A v2 row whose run has no open is structurally broken, but the design
	// keeps a mixed or unverified trail UNASSESSABLE as a whole.
	if err := a.RecordRequired(Event{Agent: "demo", SchemaVersion: 2, RecordType: "decision", RunID: testRunID, Tool: "initialize", Decision: "method-allow"}); err != nil {
		t.Fatal(err)
	}
	v2Only := mustRead(t, path)
	if got := AssessRuns(v2Only, true, now)[0].Verdict; got != "BROKEN" {
		t.Fatalf("verified run without open = %s, want BROKEN", got)
	}
	if got := AssessRuns(v2Only, false, now)[0].Verdict; got != "UNASSESSABLE" {
		t.Fatalf("unverified run without open = %s, want UNASSESSABLE", got)
	}
	if err := a.Record(Event{Agent: "demo", Tool: "read", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	if got := AssessRuns(mustRead(t, path), true, now)[0].Verdict; got != "UNASSESSABLE" {
		t.Fatalf("mixed trail with run without open = %s, want UNASSESSABLE", got)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
