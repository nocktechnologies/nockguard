package audit

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// N9870: Verify must let a caller tell a REAL chain/signature break (TamperError,
// errors.Is ErrTamper) apart from a benign read/scan failure (ScanError, errors.Is
// ErrScan) so the wall never fires a tamper banner on a long-line read glitch.

// A tampered HMAC trail classifies as ErrTamper (not ErrScan).
func TestVerifyTamperIsTamperError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	key := []byte("test-hmac-key")

	a, err := New(path, WithSigningKey(key))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if err := a.Record(Event{Agent: "kit", Tool: "t", Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	a.Close()

	// Flip a MIDDLE entry — breaks the signature chain at that line.
	data, _ := os.ReadFile(path)
	tampered := strings.Replace(string(data), `"decision":"allow"`, `"decision":"deny"`, 1)
	if tampered == string(data) {
		t.Fatal("tamper substitution did not match")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}

	n, err := Verify(path, key)
	if err == nil {
		t.Fatal("tampered trail verified clean; expected an error")
	}
	if !errors.Is(err, ErrTamper) {
		t.Fatalf("tamper error must satisfy errors.Is(ErrTamper); got %v", err)
	}
	if errors.Is(err, ErrScan) {
		t.Fatalf("tamper error must NOT be classified as a scan error; got %v", err)
	}
	var te *TamperError
	if !errors.As(err, &te) {
		t.Fatalf("tamper error must be a *TamperError; got %T", err)
	}
	if n < 1 {
		t.Fatalf("Verify should return the 1-based break line; got n=%d", n)
	}
}

// The same guarantee on the non-repudiable Ed25519 path.
func TestVerifyEd25519TamperIsTamperError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	a, err := New(path, WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := a.Record(Event{Agent: "kit", Tool: "t", Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	a.Close()

	data, _ := os.ReadFile(path)
	tampered := strings.Replace(string(data), `"tool":"t"`, `"tool":"x"`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = VerifyEd25519(path, pub)
	if err == nil {
		t.Fatal("tampered Ed25519 trail verified clean; expected an error")
	}
	if !errors.Is(err, ErrTamper) {
		t.Fatalf("Ed25519 tamper error must satisfy errors.Is(ErrTamper); got %v", err)
	}
	if errors.Is(err, ErrScan) {
		t.Fatalf("Ed25519 tamper error must NOT be a scan error; got %v", err)
	}
}

// A clean trail verifies with no error and the full count.
func TestVerifyCleanTrailNoError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	key := []byte("test-hmac-key")

	a, err := New(path, WithSigningKey(key))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := a.Record(Event{Agent: "kit", Tool: "t", Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	a.Close()

	n, err := Verify(path, key)
	if err != nil {
		t.Fatalf("clean trail should verify; got %v", err)
	}
	if n != 5 {
		t.Fatalf("expected 5 verified entries, got %d", n)
	}
}

// The crux of N9870: a legitimately long, VALIDLY SIGNED audit line that exceeds
// the scanner cap must surface as a ScanError (ErrScan / unavailable), NEVER as a
// tamper — even though it aborts the walk with fewer entries than the signed
// high-water-mark records. This pins the ordering invariant that the scan-error
// check runs BEFORE checkHighWaterMark; otherwise the short read would launder
// itself into a false "trail truncated" tamper. The cap is shrunk via the package
// var so the test costs a few KB, not 8 MiB.
func TestVerifyOversizedLineIsScanErrorNotTamper(t *testing.T) {
	orig := scanBufferCap
	scanBufferCap = 4096
	defer func() { scanBufferCap = orig }()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	key := []byte("test-hmac-key")

	a, err := New(path, WithSigningKey(key))
	if err != nil {
		t.Fatal(err)
	}
	// Two normal short entries, then one legitimately long (validly signed) entry
	// whose JSON exceeds the 4 KiB cap. hwm.Count becomes 3; the walk verifies 2
	// short lines and then hits the over-long line.
	if err := a.Record(Event{Agent: "kit", Tool: "t", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Record(Event{Agent: "kit", Tool: "t", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	// The long entry must exceed bufio.Scanner's 64 KiB initial buffer for the
	// shrunk maxTokenSize (4 KiB) to trip ErrTooLong; 100 KB does.
	if err := a.Record(Event{Agent: "kit", Tool: "t", Decision: "allow", Reason: strings.Repeat("A", 100000)}); err != nil {
		t.Fatal(err)
	}
	a.Close()

	n, err := Verify(path, key)
	if err == nil {
		t.Fatal("oversized line should produce a scan error; got nil")
	}
	if !errors.Is(err, ErrScan) {
		t.Fatalf("oversized line must be classified as a scan error (ErrScan); got %v", err)
	}
	if errors.Is(err, ErrTamper) {
		t.Fatalf("oversized-line read glitch must NOT be classified as tamper; got %v", err)
	}
	var se *ScanError
	if !errors.As(err, &se) {
		t.Fatalf("scan error must be a *ScanError; got %T", err)
	}
	// It aborted before the hwm count (2 verified, hwm=3) yet did NOT become a
	// truncation tamper — the ordering guard held.
	if n != 2 {
		t.Fatalf("expected 2 entries read before the over-long line, got %d", n)
	}
}

// With the real cap restored, the same long-but-valid line verifies clean: the
// 8 MiB cap means legitimately long audit lines no longer error at all.
func TestVerifyLongLineUnderCapVerifiesClean(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	key := []byte("test-hmac-key")

	a, err := New(path, WithSigningKey(key))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Record(Event{Agent: "kit", Tool: "t", Decision: "allow", Reason: strings.Repeat("A", 200000)}); err != nil {
		t.Fatal(err)
	}
	a.Close()

	n, err := Verify(path, key)
	if err != nil {
		t.Fatalf("a 200 KB line is well under the %d-byte cap and must verify; got %v", MaxTrailLineBytes, err)
	}
	if n != 1 {
		t.Fatalf("expected 1 verified entry, got %d", n)
	}
}
