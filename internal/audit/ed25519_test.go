package audit

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Phase 4 follow-up — non-repudiable audit. Ed25519 is asymmetric: a private key
// signs, and ANYONE with the public key can verify WHO signed without ever
// holding the signing key. That turns "tamper-evident" (HMAC, shared key,
// forgeable by the key holder) into "non-repudiable" (court-credible), aligned
// with the emerging IETF agent-audit-trail draft.

func recordN(t *testing.T, path string, priv ed25519.PrivateKey, n int) {
	t.Helper()
	a, err := New(path, WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := a.Record(Event{Agent: "kit", Tool: "nockcc_kill_switch_set", Decision: "approval-granted", Reason: "approved by human"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEd25519SignAndVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil) // nil rand => crypto/rand
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recordN(t, path, priv, 3)

	n, err := VerifyEd25519(path, pub)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if n != 3 {
		t.Errorf("expected 3 entries verified, got %d", n)
	}
}

func TestEd25519TamperBreaksChain(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recordN(t, path, priv, 3)

	// Tamper: flip a granted decision to a denied one on the middle entry.
	data, _ := os.ReadFile(path)
	tampered := strings.Replace(string(data), `"decision":"approval-granted"`, `"decision":"approval-denied"`, 1)
	os.WriteFile(path, []byte(tampered), 0644)

	if _, err := VerifyEd25519(path, pub); err == nil {
		t.Error("a tampered entry must break Ed25519 verification")
	}
}

func TestEd25519WrongPublicKeyRejected(t *testing.T) {
	// Non-repudiation property: only the matching public key verifies. A trail
	// signed by priv1 must NOT verify under an unrelated pub2.
	pub1, priv1, _ := ed25519.GenerateKey(nil)
	pub2, _, _ := ed25519.GenerateKey(nil)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recordN(t, path, priv1, 2)

	if _, err := VerifyEd25519(path, pub2); err == nil {
		t.Error("an unrelated public key must NOT verify the trail")
	}
	if _, err := VerifyEd25519(path, pub1); err != nil {
		t.Errorf("the matching public key must verify the trail: %v", err)
	}
}

// TestKeyFromHexRoundTrip proves the env-loading path: a key signed via the
// 32-byte seed (the compact env form) verifies under the public key parsed from
// hex — i.e. how a deployment actually loads the signer and a verifier the pubkey.
func TestKeyFromHexRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	seedHex := hex.EncodeToString(priv.Seed())
	pubHex := hex.EncodeToString(pub)

	loadedPriv, err := PrivateKeyFromHex(seedHex)
	if err != nil {
		t.Fatalf("PrivateKeyFromHex(seed): %v", err)
	}
	loadedPub, err := PublicKeyFromHex(pubHex)
	if err != nil {
		t.Fatalf("PublicKeyFromHex: %v", err)
	}

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recordN(t, path, loadedPriv, 2)
	if _, err := VerifyEd25519(path, loadedPub); err != nil {
		t.Errorf("trail signed by seed-loaded key must verify under hex-loaded pubkey: %v", err)
	}

	// Full 64-byte private key form is also accepted.
	if _, err := PrivateKeyFromHex(hex.EncodeToString(priv)); err != nil {
		t.Errorf("PrivateKeyFromHex(full 64-byte key): %v", err)
	}
	// Garbage is rejected, not silently accepted.
	if _, err := PrivateKeyFromHex("not-hex"); err == nil {
		t.Error("PrivateKeyFromHex must reject non-hex input")
	}
	if _, err := PublicKeyFromHex(hex.EncodeToString([]byte("short"))); err == nil {
		t.Error("PublicKeyFromHex must reject a wrong-length key")
	}
}
