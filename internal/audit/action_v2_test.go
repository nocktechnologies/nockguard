package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestV2RunSequenceIsUniqueUnderConcurrentRetries(t *testing.T) {
	key := []byte("v2-concurrent-signing-key-0123456789")
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := New(path, WithSigningKey(key))
	if err != nil {
		t.Fatal(err)
	}
	const workers = 8
	const each = 12
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				ev := Event{Agent: "mira", Tool: "tool", Decision: "allow", SchemaVersion: 2, RecordType: "decision", RunID: "00112233445566778899aabbccddeeff"}
				if err := a.RecordRequired(ev); err != nil {
					t.Errorf("worker %d write %d: %v", worker, i, err)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rows := readLines(t, path)
	if len(rows) != workers*each {
		t.Fatalf("rows=%d; want %d", len(rows), workers*each)
	}
	for i, row := range rows {
		want := uint64(i + 1)
		value, ok := row["run_seq"].(float64)
		if !ok || uint64(value) != want {
			t.Fatalf("row %d run_seq=%v; want %d; bytes=%s", i, row["run_seq"], want, data)
		}
	}
	if _, err := Verify(path, key); err != nil {
		t.Fatalf("concurrent v2 trail did not verify: %v", err)
	}
}

func TestV2RejectsCallerSequenceAndDispatchWithoutActionID(t *testing.T) {
	runID := "00112233445566778899aabbccddeeff"
	for _, tc := range []struct {
		name  string
		event Event
	}{
		{name: "dispatch requires action id", event: Event{Agent: "mira", Tool: "tool", Decision: "dispatch", SchemaVersion: 2, RecordType: "decision", RunID: runID}},
		{name: "run sequence is writer assigned", event: Event{Agent: "mira", Tool: "tool", Decision: "allow", SchemaVersion: 2, RecordType: "decision", RunID: runID, RunSeq: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := New(filepath.Join(t.TempDir(), "audit.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			if err := a.RecordRequired(tc.event); err == nil {
				t.Fatalf("invalid v2 event was accepted: %+v", tc.event)
			}
		})
	}
}

func TestV2StrictEnvelopeRequiresCanonicalOptionalFields(t *testing.T) {
	runID := "00112233445566778899aabbccddeeff"
	good := fmt.Sprintf(`{"ts":"t","agent":"a","tool":"x","decision":"allow","schema_version":2,"record_type":"decision","run_id":%q,"run_seq":1}`, runID)
	for _, tc := range []struct {
		name, line string
	}{
		{"empty omitted field present", good[:len(good)-1] + `,"cause":""}`},
		{"case folded alias", good[:len(good)-1] + `,"Schema_Version":2}`},
		{"wrong required type", strings.Replace(good, `"run_seq":1`, `"run_seq":"1"`, 1)},
		{"nested duplicate", good[:len(good)-1] + `,"extension":{"a":1,"a":2}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ev Event
			if err := json.Unmarshal([]byte(tc.line), &ev); err != nil {
				return // malformed JSON types are rejected by the typed decode.
			}
			if err := validateAuditLine([]byte(tc.line), ev); err == nil {
				t.Fatalf("accepted malformed v2 envelope: %s", tc.line)
			}
		})
	}
	var ev Event
	if err := json.Unmarshal([]byte(good), &ev); err != nil {
		t.Fatal(err)
	}
	if err := validateAuditLine([]byte(good), ev); err != nil {
		t.Fatalf("valid v2 decision rejected: %v", err)
	}
}

func TestV2RejectsEmptyOrZeroInheritedOptionalFields(t *testing.T) {
	runID := "00112233445566778899aabbccddeeff"
	base := fmt.Sprintf(`{"ts":"t","agent":"a","tool":"x","decision":"allow","schema_version":2,"record_type":"decision","run_id":%q,"run_seq":1`, runID)
	for _, field := range []string{
		`"reason":""`, `"reason":null`, `"approval_actor":""`, `"nock_id":0`,
		`"pr":""`, `"review_id":""`, `"parent_audit_seq":0`,
		`"session_id":""`, `"key_id":""`, `"sig":""`,
	} {
		line := []byte(base + "," + field + "}")
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		if err := validateAuditLine(line, ev); err == nil {
			t.Errorf("v2 reader accepted a zero or empty omitempty field: %s", field)
		}
	}
}
