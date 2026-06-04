package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func readLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit file: %v", err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("audit line is not valid JSON: %v\nline: %s", err, sc.Text())
		}
		out = append(out, m)
	}
	return out
}

func TestDisabledWhenNoPath(t *testing.T) {
	a, err := New("")
	if err != nil {
		t.Fatalf("New(\"\"): %v", err)
	}
	if a.Enabled() {
		t.Error("auditor with empty path must be disabled")
	}
	var nilA *Auditor
	if nilA.Enabled() {
		t.Error("nil auditor must report disabled")
	}
	// Record on a disabled auditor is a safe no-op.
	if err := a.Record(Event{Agent: "kit", Tool: "x", Decision: "allow"}); err != nil {
		t.Errorf("Record on disabled auditor should be a no-op, got %v", err)
	}
	if err := nilA.Record(Event{}); err != nil {
		t.Errorf("Record on nil auditor should be a no-op, got %v", err)
	}
}

func TestNewCreatesParentDirs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "logs", "audit.jsonl")
	a, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer a.Close()
	if !a.Enabled() {
		t.Fatal("auditor with a path should be enabled")
	}
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Errorf("parent dir should have been created: %v", err)
	}
}

func TestRecordWritesStructuredEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2026, 6, 3, 18, 30, 0, 0, time.UTC)
	a.clock = func() time.Time { return fixed }

	if err := a.Record(Event{Agent: "kit", Tool: "nockcc_kill_switch_set", Decision: "deny", Reason: "policy"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	a.Close()

	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("expected 1 audit line, got %d", len(lines))
	}
	ev := lines[0]
	if ev["agent"] != "kit" || ev["tool"] != "nockcc_kill_switch_set" || ev["decision"] != "deny" || ev["reason"] != "policy" {
		t.Errorf("unexpected event fields: %v", ev)
	}
	if ev["ts"] != fixed.Format(time.RFC3339) {
		t.Errorf("timestamp = %v, want %v", ev["ts"], fixed.Format(time.RFC3339))
	}
}

func TestRecordOmitsEmptyReason(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, _ := New(path)
	if err := a.Record(Event{Agent: "kit", Tool: "read_file", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	a.Close()
	lines := readLines(t, path)
	if _, present := lines[0]["reason"]; present {
		t.Error("empty reason should be omitted from the JSON line")
	}
}

func TestRecordAppendsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a1, _ := New(path)
	a1.Record(Event{Agent: "kit", Tool: "a", Decision: "allow"})
	a1.Close()

	a2, _ := New(path) // reopen — must append, not truncate
	a2.Record(Event{Agent: "kit", Tool: "b", Decision: "deny"})
	a2.Close()

	lines := readLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines after reopen+append, got %d", len(lines))
	}
	if lines[0]["tool"] != "a" || lines[1]["tool"] != "b" {
		t.Errorf("append order wrong: %v", lines)
	}
}

func TestConcurrentRecordIsSafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, _ := New(path)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = a.Record(Event{Agent: "kit", Tool: "t", Decision: "allow"})
		}()
	}
	wg.Wait()
	a.Close()

	lines := readLines(t, path) // every line must be intact, valid JSON (no interleaving)
	if len(lines) != 50 {
		t.Fatalf("expected 50 intact lines, got %d", len(lines))
	}
}
