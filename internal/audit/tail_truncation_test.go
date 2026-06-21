package audit

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// N8154 — tail-truncation detection. A pure hash chain catches edits, reorders,
// inserts, and MID-deletes (the next entry's prev-sig link breaks), but NOT
// lopping the tail: a truncated PREFIX still chains clean. A signed
// high-water-mark (entry count + the last entry's signature) closes that gap so
// "nothing was removed" becomes provable. Closes 2026-06-07 audit finding #6.

// truncateLastLine removes the final newline-terminated entry from a JSONL file,
// simulating an attacker with write access lopping the tail of the trail. The
// remaining prefix is left intact (and still hash-chains clean).
func truncateLastLine(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("need >=2 lines to truncate, have %d", len(lines))
	}
	out := strings.Join(lines[:len(lines)-1], "\n") + "\n"
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestEd25519TailTruncationIsDetected is the core N8154 contract: after the
// signed high-water-mark exists, lopping the tail of an otherwise-clean chain
// must be detected. Without the high-water-mark this FAILS (the truncated prefix
// verifies clean) — that failure IS the gap finding #6 names.
func TestEd25519TailTruncationIsDetected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recordN(t, path, priv, 4)

	if _, err := VerifyEd25519(path, pub); err != nil {
		t.Fatalf("the full trail must verify: %v", err)
	}

	// Attacker lops the last entry. The remaining 3-entry prefix still
	// hash-chains clean, so a pure chain walk PASSES — the gap. The signed
	// high-water-mark must catch that the trail is now SHORTER than it was.
	truncateLastLine(t, path)

	if _, err := VerifyEd25519(path, pub); err == nil {
		t.Error("tail truncation must be detected (the signed high-water-mark proves an entry was removed)")
	}
}

// TestEd25519SignedTrailWithDeletedHWMIsRejected documents the N8182 hardening:
// a signed non-empty trail missing its .hwm sidecar is now treated as suspicious
// (the sidecar may have been deleted alongside a tail truncation). N8154 writes
// .hwm on every Record(), so any live signed trail will always have one unless
// it was explicitly removed. Pre-N8154 trails (e.g. mira.audit.jsonl) acquired a
// .hwm the first time a new entry was appended after the N8154 deploy, so they
// are covered too. The old behaviour (pass silently on absent .hwm) was replaced
// by TestDeletedHighWaterMarkIsDetectedOnSignedTrail.
func TestEd25519SignedTrailWithDeletedHWMIsRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recordN(t, path, priv, 3)

	if err := os.Remove(path + ".hwm"); err != nil {
		t.Fatalf("could not remove hwm sidecar: %v", err)
	}

	if _, err := VerifyEd25519(path, pub); err == nil {
		t.Error("signed trail with deleted .hwm must now be rejected — N8182 hardening")
	}
}

// TestHMACTailTruncationIsDetected proves the high-water-mark closes the gap in
// the symmetric HMAC mode too, not only Ed25519.
func TestHMACTailTruncationIsDetected(t *testing.T) {
	key := []byte("test-hmac-key-32-bytes-long-okay")
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := New(path, WithSigningKey(key))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if err := a.Record(Event{Agent: "kit", Tool: "x", Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(path, key); err != nil {
		t.Fatalf("the full HMAC trail must verify: %v", err)
	}
	truncateLastLine(t, path)
	if _, err := Verify(path, key); err == nil {
		t.Error("HMAC: tail truncation must be detected via the high-water-mark")
	}
}

// TestDeletedHighWaterMarkIsDetectedOnSignedTrail proves N8182 finding #2: when
// an attacker deletes the .hwm sidecar alongside a tail truncation, the absence
// of the sidecar must itself be flagged as suspicious on a signed trail that has
// entries. An absent sidecar on an unsigned or empty trail is fine; the gap is
// specifically a signed non-empty trail with no checkpoint.
func TestDeletedHighWaterMarkIsDetectedOnSignedTrail(t *testing.T) {
	t.Run("ed25519", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		recordN(t, path, priv, 3)

		if err := os.Remove(path + ".hwm"); err != nil {
			t.Fatalf("could not remove hwm sidecar: %v", err)
		}

		if _, err := VerifyEd25519(path, pub); err == nil {
			t.Error("missing .hwm on a signed non-empty trail must be detected")
		}
	})

	t.Run("hmac", func(t *testing.T) {
		key := []byte("test-hmac-key-32-bytes-long-okay")
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		a, err := New(path, WithSigningKey(key))
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			if err := a.Record(Event{Agent: "kit", Tool: "x", Decision: "allow"}); err != nil {
				t.Fatal(err)
			}
		}
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}

		if err := os.Remove(path + ".hwm"); err != nil {
			t.Fatalf("could not remove hwm sidecar: %v", err)
		}

		if _, err := Verify(path, key); err == nil {
			t.Error("missing .hwm on a signed non-empty HMAC trail must be detected")
		}
	})
}

// TestForgedHighWaterMarkRejected proves an attacker who truncates the trail and
// rewrites the sidecar to a matching lower count cannot hide it: the checkpoint
// is signed, so a forged (wrong-key / bogus) signature is rejected.
func TestForgedHighWaterMarkRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recordN(t, path, priv, 4)
	truncateLastLine(t, path) // 3 entries remain on disk, still chain-clean

	// Forge an hwm claiming count=3 with a bogus signature (no signing key).
	forged := `{"count":3,"last_sig":"abc","sig":"deadbeef"}` + "\n"
	if err := os.WriteFile(path+".hwm", []byte(forged), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEd25519(path, pub); err == nil {
		t.Error("a forged high-water-mark (bogus signature) must be rejected")
	}
}
