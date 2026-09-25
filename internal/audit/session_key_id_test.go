package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// N10647 (PR 4 of the unified receipt plan): session_id and key_id are
// additive, omitempty Event fields. This file proves: (1) their absence
// leaves old serialization byte-identical, (2) session_id is stamped from
// NOCKLOCK_SESSION_ID and omitted when unset, (3) key_id is stamped only for
// Ed25519-signed trails as hex(sha256(pub)) and never for HMAC trails, (4) a
// signed trail with session_id tampered fails verification, and (5) a trail
// written by pre-change code still verifies today.

// TestGoldenEventNoSessionOrKeyIDMarshalsUnchanged proves the hard backward
// compatibility requirement: an event with neither new field set produces
// EXACTLY the JSON line origin/main produced before these fields existed.
// The golden line below was captured by running the pre-change Record()
// against a fixed clock (git show origin/main:internal/audit/audit.go), not
// hand-written, so it is a real receipt of prior behavior, not a guess.
func TestGoldenEventNoSessionOrKeyIDMarshalsUnchanged(t *testing.T) {
	t.Setenv(nocklockSessionIDEnv, "") // guard against a leaked env from the caller's own nocklock wrap
	const golden = `{"ts":"2026-06-03T18:30:00Z","agent":"kit","tool":"nockcc_kill_switch_set","decision":"deny","reason":"policy"}` + "\n"

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
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != golden {
		t.Fatalf("event with no session_id/key_id changed serialization\n got:  %s\n want: %s", got, golden)
	}
}

// TestSessionIDStampedFromEnvOmittedWhenUnset covers point 2: with
// NOCKLOCK_SESSION_ID set, written events carry it; unset, the key is absent
// entirely (not present-and-empty) from the JSON line.
func TestSessionIDStampedFromEnvOmittedWhenUnset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	t.Setenv(nocklockSessionIDEnv, "sess-abc123")
	if err := a.Record(Event{Agent: "kit", Tool: "t", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}

	t.Setenv(nocklockSessionIDEnv, "")
	if err := a.Record(Event{Agent: "kit", Tool: "t", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	a.Close()

	lines := readLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	if lines[0]["session_id"] != "sess-abc123" {
		t.Errorf("session_id = %v, want sess-abc123", lines[0]["session_id"])
	}
	if _, present := lines[1]["session_id"]; present {
		t.Errorf("session_id must be absent from the JSON line when NOCKLOCK_SESSION_ID is unset, got %v", lines[1]["session_id"])
	}
}

// TestKeyIDEd25519PresentHMACAbsent covers point 3: an Ed25519-signed trail
// stamps key_id = hex(sha256(pub)); an HMAC-signed trail never carries key_id.
func TestKeyIDEd25519PresentHMACAbsent(t *testing.T) {
	t.Setenv(nocklockSessionIDEnv, "")

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	wantKeyID := func() string {
		sum := sha256.Sum256(pub)
		return hex.EncodeToString(sum[:])
	}()

	edPath := filepath.Join(t.TempDir(), "ed.jsonl")
	edA, err := New(edPath, WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	if err := edA.Record(Event{Agent: "kit", Tool: "t", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	edA.Close()

	edLines := readLines(t, edPath)
	if got := edLines[0]["key_id"]; got != wantKeyID {
		t.Errorf("Ed25519 trail key_id = %v, want %s", got, wantKeyID)
	}

	hmacPath := filepath.Join(t.TempDir(), "hmac.jsonl")
	hmacA, err := New(hmacPath, WithSigningKey([]byte("shared-secret-key-material")))
	if err != nil {
		t.Fatal(err)
	}
	if err := hmacA.Record(Event{Agent: "kit", Tool: "t", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	hmacA.Close()

	hmacLines := readLines(t, hmacPath)
	if _, present := hmacLines[0]["key_id"]; present {
		t.Errorf("HMAC-signed trail must never carry key_id, got %v", hmacLines[0]["key_id"])
	}
}

// TestTamperedSessionIDBreaksEd25519Verify covers point 4 and the signature
// scope requirement: session_id (when present) is part of the canonical
// payload the Ed25519 signature covers, so editing it in a signed line must
// break verification just like tampering any other field.
func TestTamperedSessionIDBreaksEd25519Verify(t *testing.T) {
	t.Setenv(nocklockSessionIDEnv, "sess-original")

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
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

	// Sanity: the untampered trail verifies clean.
	if n, err := VerifyEd25519(path, pub); err != nil || n != 3 {
		t.Fatalf("untampered trail must verify clean, got n=%d err=%v", n, err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), `"session_id":"sess-original"`, `"session_id":"sess-forged"`, 1)
	if tampered == string(data) {
		t.Fatal("test setup broken: session_id literal not found in trail to tamper")
	}
	if err := os.WriteFile(path, []byte(tampered), 0644); err != nil {
		t.Fatal(err)
	}

	_, err = VerifyEd25519(path, pub)
	if err == nil {
		t.Fatal("editing session_id on a signed line must fail verification")
	}
	if !errors.Is(err, ErrTamper) {
		t.Errorf("session_id tamper must classify as ErrTamper, got %v", err)
	}
}

// TestOldTrailWithoutNewFieldsStillVerifies covers point 5: a trail written
// entirely by pre-change code (no session_id/key_id ever set on any Event)
// must still verify under today's VerifyEd25519. Fixture captured by running
// the pre-change Record()/Close() against a fixed clock and a fixed seed, so
// it is a real prior-code artifact, including its .hwm sidecar (checkHighWaterMark
// fails a signed non-empty trail with no sidecar).
func TestOldTrailWithoutNewFieldsStillVerifies(t *testing.T) {
	const oldTrail = `{"ts":"2026-06-03T18:30:00Z","agent":"kit","tool":"t","decision":"allow","sig":"fa9781f3db6197b76df51e103605da6af461ff2fa731d8507c7f9e5ed162038cae1655a1c6157d8a9b16eeac945e389b99ae19ea238aace2c8eda52f6319340c"}
{"ts":"2026-06-03T18:30:00Z","agent":"kit","tool":"t","decision":"allow","sig":"ccd975442e3e21f5791802a000d4c633ad9c0ab3a0b3f905949b1ecae667fcdc77df374a9f1c83438c0da0425cd2b21edf36d46420974b714231f058e9bd4f08"}
{"ts":"2026-06-03T18:30:00Z","agent":"kit","tool":"t","decision":"allow","sig":"299b20feff960db2920e3ec18608b969c10e7bdc2d77bf24d9f43af7d2c4f0c64bc5ac56ed71e126bf50735893a83594cdc815ed5804c4ec593a2731905fe504"}
`
	const oldHWM = `{"count":3,"last_sig":"299b20feff960db2920e3ec18608b969c10e7bdc2d77bf24d9f43af7d2c4f0c64bc5ac56ed71e126bf50735893a83594cdc815ed5804c4ec593a2731905fe504","sig":"1e9b230abd2cc124987943881c951d147629140ee1a0fd90889a052cc8e91e5a1886e7587c2ebdeb4fe301f66184d73ee1915c24a707601ffd5333213bf0ca04"}
`
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32))
	pub := priv.Public().(ed25519.PublicKey)

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, []byte(oldTrail), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".hwm", []byte(oldHWM), 0644); err != nil {
		t.Fatal(err)
	}

	n, err := VerifyEd25519(path, pub)
	if err != nil {
		t.Fatalf("a trail written before session_id/key_id existed must still verify: %v", err)
	}
	if n != 3 {
		t.Errorf("expected 3 entries verified, got %d", n)
	}
}

// TestCallerKeyIDNeverSurvives (fix round, N10647): a caller-supplied
// Event.KeyID must never reach the JSON line as-is. In HMAC and unsigned
// modes it must be dropped entirely (key_id absent); in Ed25519 mode it must
// be overwritten with the Auditor's own hex(sha256(pub)), never the caller's
// forged value. Trusting caller input here would let any caller forge
// attribution to a signing key that never signed the entry.
func TestCallerKeyIDNeverSurvives(t *testing.T) {
	t.Setenv(nocklockSessionIDEnv, "")

	// HMAC mode: forged KeyID must not survive.
	hmacPath := filepath.Join(t.TempDir(), "hmac.jsonl")
	hmacA, err := New(hmacPath, WithSigningKey([]byte("shared-secret-key-material")))
	if err != nil {
		t.Fatal(err)
	}
	if err := hmacA.Record(Event{Agent: "kit", Tool: "t", Decision: "allow", KeyID: "forged"}); err != nil {
		t.Fatal(err)
	}
	hmacA.Close()
	hmacLines := readLines(t, hmacPath)
	if got, present := hmacLines[0]["key_id"]; present {
		t.Errorf("HMAC trail must never carry a caller-supplied key_id, got %v", got)
	}

	// Unsigned mode: forged KeyID must not survive.
	unsignedPath := filepath.Join(t.TempDir(), "unsigned.jsonl")
	unsignedA, err := New(unsignedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := unsignedA.Record(Event{Agent: "kit", Tool: "t", Decision: "allow", KeyID: "forged"}); err != nil {
		t.Fatal(err)
	}
	unsignedA.Close()
	unsignedLines := readLines(t, unsignedPath)
	if got, present := unsignedLines[0]["key_id"]; present {
		t.Errorf("unsigned trail must never carry a caller-supplied key_id, got %v", got)
	}

	// Ed25519 mode: forged KeyID must be overwritten with the real key_id.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	wantKeyID := func() string {
		sum := sha256.Sum256(pub)
		return hex.EncodeToString(sum[:])
	}()
	edPath := filepath.Join(t.TempDir(), "ed.jsonl")
	edA, err := New(edPath, WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	if err := edA.Record(Event{Agent: "kit", Tool: "t", Decision: "allow", KeyID: "forged"}); err != nil {
		t.Fatal(err)
	}
	edA.Close()
	edLines := readLines(t, edPath)
	if got := edLines[0]["key_id"]; got != wantKeyID {
		t.Errorf("Ed25519 trail key_id = %v, want %s (caller-forged value must be overwritten)", got, wantKeyID)
	}
	if edLines[0]["key_id"] == "forged" {
		t.Fatal("caller-supplied key_id 'forged' must never survive into the Ed25519 line")
	}
}
