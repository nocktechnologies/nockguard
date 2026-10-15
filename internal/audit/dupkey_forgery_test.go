package audit

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// N8179 regression — duplicate-JSON-key audit-line forgery.
//
// The verifier decodes each raw line into the typed Event then re-marshals and
// checks the signature over the re-canonicalized bytes. Go's encoding/json is
// LAST-WINS on duplicate keys, so a forged line that PREPENDS a contradicting
// "decision":"deny" before the originally-signed body decodes Decision="allow",
// re-canonicalizes to exactly the signed bytes, and passes signature
// verification — while a human reading the raw JSONL sees "deny". The hash chain
// links by the sig string so it stays intact too.
//
// The fix rejects any line that is not in canonical (one-key-each) form before
// signature checking, on BOTH verify paths. These tests build a real signed
// trail, forge the first line by injecting a duplicate "decision" key, and
// assert verification now FAILS (it passed before the fix).

// forgeDuplicateDecisionKey takes a canonical signed audit line and returns a
// byte-forged variant that prepends a contradicting "decision":"deny" key. Go's
// last-wins decode collapses it back to the original (signed) decision, so the
// signature still matches the re-canonicalized bytes.
func forgeDuplicateDecisionKey(t *testing.T, line []byte) []byte {
	t.Helper()
	line = bytes.TrimSpace(line)
	if len(line) == 0 || line[0] != '{' {
		t.Fatalf("expected a JSON object line, got: %s", line)
	}
	// Inject the forged key immediately after the opening brace.
	forged := append([]byte(`{"decision":"deny",`), line[1:]...)
	// Sanity: the forged line must still decode (last-wins) to the original
	// decision, otherwise the test is not exercising the parser differential.
	var ev Event
	if err := json.Unmarshal(forged, &ev); err != nil {
		t.Fatalf("forged line does not decode: %v\nline: %s", err, forged)
	}
	if ev.Decision != "allow" {
		t.Fatalf("forged line should decode (last-wins) to the original allow decision, got %q", ev.Decision)
	}
	return forged
}

func firstLine(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read trail: %v", err)
	}
	idx := bytes.IndexByte(data, '\n')
	if idx < 0 {
		return data
	}
	return data[:idx]
}

func writeFirstLine(t *testing.T, path string, newFirst []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read trail: %v", err)
	}
	idx := bytes.IndexByte(data, '\n')
	rest := []byte{}
	if idx >= 0 {
		rest = data[idx:] // keep the newline + remaining lines
	}
	out := append(append([]byte{}, newFirst...), rest...)
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatalf("write forged trail: %v", err)
	}
}

func TestDuplicateDecisionKeyForgeryRejectedHMAC(t *testing.T) {
	key := []byte("test-hmac-key-32-bytes-long-aaaa")
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	a, err := New(path, WithSigningKey(key))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Record(Event{Agent: "kit", Tool: "nockcc_spend_add", Decision: "allow", Reason: "allow-rule"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Record(Event{Agent: "kit", Tool: "nockcc_nock_list", Decision: "allow", Reason: "allow-rule"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	// Baseline: the genuine trail verifies.
	if _, err := Verify(path, key); err != nil {
		t.Fatalf("genuine trail must verify: %v", err)
	}

	// Forge the first line with a duplicate "decision":"deny" key.
	forged := forgeDuplicateDecisionKey(t, firstLine(t, path))
	writeFirstLine(t, path, forged)

	// The forgery shows "deny" to a human but the OLD verifier accepted it as
	// PROTECTED. It must now FAIL verification.
	if _, err := Verify(path, key); err == nil {
		t.Fatal("duplicate-decision-key forgery must FAIL HMAC verification — non-canonical line accepted (N8179 regression)")
	}
}

func TestDuplicateDecisionKeyForgeryRejectedEd25519(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	a, err := New(path, WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Record(Event{Agent: "kit", Tool: "nockcc_spend_add", Decision: "allow", Reason: "allow-rule"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Record(Event{Agent: "kit", Tool: "nockcc_nock_list", Decision: "allow", Reason: "allow-rule"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	// Baseline: the genuine trail verifies under the public key.
	if _, err := VerifyEd25519(path, pub); err != nil {
		t.Fatalf("genuine trail must verify: %v", err)
	}

	forged := forgeDuplicateDecisionKey(t, firstLine(t, path))
	writeFirstLine(t, path, forged)

	if _, err := VerifyEd25519(path, pub); err == nil {
		t.Fatal("duplicate-decision-key forgery must FAIL Ed25519 verification — non-canonical line accepted (N8179 regression)")
	}
}

// Guardrail: a normal canonical line still passes the duplicate-key check, so the
// fix does not break legitimate trails.
func TestCanonicalLinePassesDuplicateKeyCheck(t *testing.T) {
	line := []byte(`{"ts":"2026-06-20T00:00:00Z","agent":"kit","tool":"x","decision":"allow","reason":"r","sig":"abc"}`)
	if err := rejectDuplicateObjectKeys(line); err != nil {
		t.Errorf("a canonical line must pass the duplicate-key check, got: %v", err)
	}
	// Duplicate-looking text inside a string is not a JSON member and remains
	// valid.
	nested := []byte(`{"ts":"t","reason":"{\"decision\":\"deny\"}","decision":"allow","sig":"s"}`)
	if err := rejectDuplicateObjectKeys(nested); err != nil {
		t.Errorf("a line with duplicate-looking text inside a string value must pass: %v", err)
	}
	// Actual duplicate names are rejected recursively, even inside an otherwise
	// unknown extension object. The typed Event decoder would discard that object.
	nestedDuplicate := []byte(`{"ts":"t","agent":"a","tool":"x","decision":"allow","extension":{"x":1,"x":2},"sig":"s"}`)
	if err := rejectDuplicateObjectKeys(nestedDuplicate); err == nil {
		t.Fatal("nested duplicate member must be rejected")
	}
}

func TestAuditReaderRejectsUnknownCaseAliasesAndExplicitV1(t *testing.T) {
	for _, line := range []string{
		`{"ts":"t","agent":"a","tool":"x","decision":"allow","extension":true}`,
		`{"ts":"t","agent":"a","tool":"x","decision":"allow","Tool":"y"}`,
		`{"ts":"t","agent":"a","tool":"x","decision":"allow","schema_version":1}`,
	} {
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("fixture should decode before strict envelope validation: %v", err)
		}
		if err := validateAuditLine([]byte(line), ev); err == nil {
			t.Errorf("strict audit reader accepted %s", line)
		}
	}
	legacy := []byte(`{"ts":"t","agent":"a","tool":"x","decision":"allow"}`)
	var ev Event
	if err := json.Unmarshal(legacy, &ev); err != nil {
		t.Fatal(err)
	}
	if err := validateAuditLine(legacy, ev); err != nil {
		t.Fatalf("historical v1 shape rejected: %v", err)
	}
}

func TestUnknownV1ExtensionForgeryRejectedByVerifiers(t *testing.T) {
	hmacKey := []byte("legacy-envelope-key-0123456789")
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		create func(string) error
		verify func(string) error
	}{
		{
			name: "hmac",
			create: func(path string) error {
				a, err := New(path, WithSigningKey(hmacKey))
				if err != nil {
					return err
				}
				defer a.Close()
				return a.Record(Event{Agent: "kit", Tool: "read", Decision: "allow"})
			},
			verify: func(path string) error { _, err := Verify(path, hmacKey); return err },
		},
		{
			name: "ed25519",
			create: func(path string) error {
				a, err := New(path, WithEd25519Key(priv))
				if err != nil {
					return err
				}
				defer a.Close()
				return a.Record(Event{Agent: "kit", Tool: "read", Decision: "allow"})
			},
			verify: func(path string) error { _, err := VerifyEd25519(path, pub); return err },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			if err := tc.create(path); err != nil {
				t.Fatal(err)
			}
			line := bytes.Replace(firstLine(t, path), []byte(`,"sig":`), []byte(`,"extension":true,"sig":`), 1)
			writeFirstLine(t, path, line)
			if err := tc.verify(path); err == nil {
				t.Fatal("signed v1 row with an unknown extension was accepted")
			}
		})
	}
}
