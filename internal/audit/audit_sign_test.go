package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var signKey = []byte("test-signing-key-32-bytes-padding!")

func recordAll(t *testing.T, path string, key []byte, evs []Event) {
	t.Helper()
	a, err := New(path, WithSigningKey(key))
	if err != nil {
		t.Fatalf("New signed: %v", err)
	}
	for _, ev := range evs {
		if err := a.Record(ev); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func sampleEvents() []Event {
	return []Event{
		{Agent: "kit", Tool: "Read", Decision: "allow"},
		{Agent: "ash", Tool: "Bash", Decision: "block", Reason: "secret-exfil"},
		{Agent: "vale", Tool: "WebFetch", Decision: "ratelimit", Reason: "rate"},
	}
}

func readRawLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func writeRawLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
}

func TestSignedTrailVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recordAll(t, path, signKey, sampleEvents())

	rows := readLines(t, path)
	if len(rows) != 3 {
		t.Fatalf("want 3 rows, got %d", len(rows))
	}
	for i, r := range rows {
		if s, _ := r["sig"].(string); s == "" {
			t.Errorf("row %d has no signature", i)
		}
	}

	n, err := Verify(path, signKey)
	if err != nil {
		t.Fatalf("Verify clean signed trail: %v", err)
	}
	if n != 3 {
		t.Errorf("Verify count = %d, want 3", n)
	}
}

func TestVerifyDetectsEdit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recordAll(t, path, signKey, sampleEvents())

	// The cover-up an attacker wants: flip a recorded BLOCK to allow.
	lines := readRawLines(t, path)
	lines[1] = strings.Replace(lines[1], `"decision":"block"`, `"decision":"allow"`, 1)
	writeRawLines(t, path, lines)

	if _, err := Verify(path, signKey); err == nil {
		t.Fatal("expected Verify to detect the edited decision, got nil")
	}
}

func TestVerifyDetectsDeletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recordAll(t, path, signKey, sampleEvents())

	lines := readRawLines(t, path)
	lines = append(lines[:1], lines[2:]...) // drop the middle entry
	writeRawLines(t, path, lines)

	if _, err := Verify(path, signKey); err == nil {
		t.Fatal("expected Verify to detect the deleted entry, got nil")
	}
}

func TestVerifyDetectsReorder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recordAll(t, path, signKey, sampleEvents())

	lines := readRawLines(t, path)
	lines[0], lines[1] = lines[1], lines[0] // swap first two
	writeRawLines(t, path, lines)

	if _, err := Verify(path, signKey); err == nil {
		t.Fatal("expected Verify to detect the reordered entries, got nil")
	}
}

func TestVerifyWrongKeyFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recordAll(t, path, signKey, sampleEvents())

	if _, err := Verify(path, []byte("the-wrong-key")); err == nil {
		t.Fatal("expected Verify with the wrong key to fail, got nil")
	}
}

func TestUnsignedTrailIsNotSigned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := New(path) // no key
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := a.Record(Event{Agent: "kit", Tool: "Read", Decision: "allow"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	a.Close()

	for i, r := range readLines(t, path) {
		if _, ok := r["sig"]; ok {
			t.Errorf("row %d unexpectedly has a sig on an unsigned trail", i)
		}
	}
	if _, err := Verify(path, signKey); err == nil {
		t.Fatal("expected Verify of an unsigned trail to fail (not signed), got nil")
	}
}

// The chain must survive a proxy restart: a second Auditor opened on the same
// file seeds its previous signature from the file's last entry, so appended
// entries stay verifiable end to end.
func TestChainSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recordAll(t, path, signKey, sampleEvents()[:2]) // first session: 2 entries
	recordAll(t, path, signKey, sampleEvents()[2:]) // second session: appends 1 more

	n, err := Verify(path, signKey)
	if err != nil {
		t.Fatalf("Verify across reopen: %v", err)
	}
	if n != 3 {
		t.Errorf("Verify count = %d, want 3", n)
	}
}
