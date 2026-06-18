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

// TestEd25519LegacyTrailWithoutHighWaterMarkStillVerifies guards backward
// compatibility: a trail with NO high-water-mark sidecar must verify exactly as
// before. The live 247-entry mira.audit.jsonl predates the high-water-mark and
// must NOT false-TAMPER — claim-guard depends on those signatures staying valid.
func TestEd25519LegacyTrailWithoutHighWaterMarkStillVerifies(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recordN(t, path, priv, 3)

	// Simulate a legacy trail: strip any high-water-mark sidecar so only the
	// bare signed JSONL remains, exactly like a pre-N8154 trail on disk.
	_ = os.Remove(path + ".hwm")

	if _, err := VerifyEd25519(path, pub); err != nil {
		t.Errorf("a legacy trail without a high-water-mark must verify as before: %v", err)
	}
}
