package audit

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Reopening a signed trail must VERIFY the existing chain before seeding from its
// tail. Otherwise a tamper/truncation during downtime is baked in: the next
// append chains onto the broken tail and the trail verifies clean from there on.
// New() must refuse to open a trail whose chain is broken.
func TestNewRefusesToOpenTamperedChain(t *testing.T) {
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

	// Tamper a MIDDLE entry (breaks the chain at that line, not the tail).
	data, _ := os.ReadFile(path)
	tampered := strings.Replace(string(data), `"decision":"allow"`, `"decision":"deny"`, 1)
	if tampered == string(data) {
		t.Fatal("tamper substitution did not match")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}

	// Reopening must fail loud rather than silently chaining onto the broken tail.
	if _, err := New(path, WithSigningKey(key)); err == nil {
		t.Fatal("New() opened a tampered trail; expected a verification error")
	} else if !strings.Contains(err.Error(), "failed verification on open") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// A valid signed trail must reopen cleanly AND keep producing a verifiable chain
// across the restart (the seed-after-verify path stays correct).
func TestNewReopensValidChainAndAppends(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	key := []byte("test-hmac-key")

	a, err := New(path, WithSigningKey(key))
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Record(Event{Agent: "kit", Tool: "t", Decision: "allow"})
	a.Close()

	// Reopen (verifies the existing chain, then seeds) and append more.
	a2, err := New(path, WithSigningKey(key))
	if err != nil {
		t.Fatalf("valid chain should reopen cleanly: %v", err)
	}
	_ = a2.Record(Event{Agent: "kit", Tool: "t2", Decision: "deny"})
	a2.Close()

	if n, err := Verify(path, key); err != nil || n != 2 {
		t.Fatalf("expected 2 verified entries across restart, got n=%d err=%v", n, err)
	}
}

// Same guarantee on the non-repudiable Ed25519 path: New derives the public key
// from the configured private key and refuses a broken chain on open.
func TestNewRefusesTamperedEd25519Chain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	a, err := New(path, WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_ = a.Record(Event{Agent: "kit", Tool: "t", Decision: "allow"})
	}
	a.Close()

	data, _ := os.ReadFile(path)
	tampered := strings.Replace(string(data), `"tool":"t"`, `"tool":"x"`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := New(path, WithEd25519Key(priv)); err == nil {
		t.Fatal("New() opened a tampered Ed25519 trail; expected a verification error")
	}
}
