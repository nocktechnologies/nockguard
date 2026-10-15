package audit

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
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

func TestApprovalActorIsSignedAndTamperingIsRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := New(path, WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Record(Event{Agent: "kit", Tool: "deploy", Decision: "approval-granted", ApprovalActor: "local:uid:501"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEd25519(path, pub); err != nil {
		t.Fatalf("valid approval actor trail did not verify: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), `"approval_actor":"local:uid:501"`, `"approval_actor":"local:uid:502"`, 1)
	if tampered == string(data) {
		t.Fatal("approval_actor field was not serialized")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEd25519(path, pub); err == nil {
		t.Fatal("tampering with approval_actor must break Ed25519 verification")
	}
}

func TestApprovalActorAliasesAndDuplicatesAreRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := New(path, WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Record(Event{Agent: "kit", Tool: "deploy", Decision: "approval-granted", ApprovalActor: "local:uid:501"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const field = `"approval_actor":"local:uid:501"`
	for name, mutated := range map[string]string{
		"case-alias": strings.Replace(string(original), `"approval_actor"`, `"Approval_Actor"`, 1),
		"duplicate":  strings.Replace(string(original), field, field+`,`+field, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if mutated == string(original) {
				t.Fatal("test mutation did not match signed approval actor")
			}
			if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyEd25519(path, pub); !errors.Is(err, ErrTamper) {
				t.Fatalf("non-canonical actor key must be classified as tampering, got %v", err)
			}
		})
	}
}

func TestApprovalActorNullCannotCollapseToOmittedField(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	// This actor-free signed row is valid before the additive field existed.
	recordN(t, path, priv, 1)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"null": "null", "empty-string": `""`} {
		t.Run(name, func(t *testing.T) {
			mutated := strings.Replace(string(data), `,"sig":`, `,"approval_actor":`+value+`,"sig":`, 1)
			if mutated == string(data) {
				t.Fatal("could not insert approval_actor into signed row")
			}
			if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyEd25519(path, pub); !errors.Is(err, ErrTamper) {
				t.Fatalf("%s approval_actor must not collapse to omitted field: %v", name, err)
			}
		})
	}
}

func TestInvalidRequiredApprovalActorLatchesWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RecordRequired(Event{Agent: "kit", Tool: "deploy", Decision: "approval-granted", ApprovalActor: "local:uid:01"}); err == nil {
		t.Fatal("RecordRequired accepted non-canonical approval_actor")
	}
	if err := a.RecordRequired(Event{Agent: "kit", Tool: "deploy", Decision: "dispatch"}); err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("required writer did not stay latched after invalid event: %v", err)
	}
}

func TestApprovalActorValidationAppliesToRecordAndVerifiers(t *testing.T) {
	invalid := []Event{
		{Agent: "kit", Tool: "deploy", Decision: "approval-granted", ApprovalActor: "local:uid:01"},
		{Agent: "kit", Tool: "deploy", Decision: "approval-granted", ApprovalActor: "local:uid:4294967296"},
		{Agent: "kit", Tool: "deploy", Decision: "approval-granted", ApprovalActor: "caller:uid:501"},
		{Agent: "kit", Tool: "deploy", Decision: "allow", ApprovalActor: "local:uid:501"},
	}
	for _, ev := range invalid {
		t.Run(ev.Decision+"/"+ev.ApprovalActor, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			writer, err := New(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.Record(ev); err == nil {
				t.Fatalf("Record accepted invalid approval actor event %+v", ev)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}

			// A signer must not be able to create a syntactically valid chain
			// that makes a malformed/non-approval actor look trustworthy.
			for _, mode := range []string{"hmac", "ed25519"} {
				t.Run(mode, func(t *testing.T) {
					line := ev
					line.Time = "2026-06-03T18:30:00Z"
					var verifierErr error
					if mode == "hmac" {
						key := []byte("test signing key")
						canonical, marshalErr := json.Marshal(line)
						if marshalErr != nil {
							t.Fatal(marshalErr)
						}
						line.Sig = signLine(key, canonical, "")
						data, marshalErr := json.Marshal(line)
						if marshalErr != nil {
							t.Fatal(marshalErr)
						}
						path := filepath.Join(t.TempDir(), "audit.jsonl")
						if writeErr := os.WriteFile(path, append(data, '\n'), 0o600); writeErr != nil {
							t.Fatal(writeErr)
						}
						_, verifierErr = Verify(path, key)
					} else {
						_, priv, keyErr := ed25519.GenerateKey(nil)
						if keyErr != nil {
							t.Fatal(keyErr)
						}
						canonical, marshalErr := json.Marshal(line)
						if marshalErr != nil {
							t.Fatal(marshalErr)
						}
						line.Sig = signLineEd25519(priv, canonical, "")
						data, marshalErr := json.Marshal(line)
						if marshalErr != nil {
							t.Fatal(marshalErr)
						}
						path := filepath.Join(t.TempDir(), "audit.jsonl")
						if writeErr := os.WriteFile(path, append(data, '\n'), 0o600); writeErr != nil {
							t.Fatal(writeErr)
						}
						pub := priv.Public().(ed25519.PublicKey)
						_, verifierErr = VerifyEd25519(path, pub)
					}
					if !errors.Is(verifierErr, ErrTamper) {
						t.Fatalf("%s verifier accepted invalid actor: %v", mode, verifierErr)
					}
				})
			}
		})
	}
}

func TestLegacyHMACTrailWithoutApprovalActorStillVerifies(t *testing.T) {
	key := []byte("legacy hmac key")
	ev := Event{Time: "2026-06-03T18:30:00Z", Agent: "kit", Tool: "deploy", Decision: "allow"}
	canonical, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	ev.Sig = signLine(key, canonical, "")
	line, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	mark := highWaterMark{Count: 1, LastSig: ev.Sig}
	mark.Sig = signLine(key, hwmSignedBytes(mark.Count, mark.LastSig), "")
	markBytes, err := json.Marshal(mark)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "legacy.jsonl")
	if err := os.WriteFile(path, append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+hwmSuffix, append(markBytes, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := Verify(path, key); err != nil || n != 1 {
		t.Fatalf("legacy HMAC trail without approval_actor did not verify: n=%d err=%v", n, err)
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

func TestVerifyEd25519BytesMatchesFileVerifier(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "a.audit.jsonl")
	a, err := New(path, WithEd25519Key(priv))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"allow", "deny", "allow"} {
		if err := a.Record(Event{Agent: "x", Tool: "Read", Decision: d}); err != nil {
			t.Fatal(err)
		}
	}
	_ = a.Close()
	trail, _ := os.ReadFile(path)
	hwm, _ := os.ReadFile(path + hwmSuffix)
	if n, err := VerifyEd25519Bytes(trail, hwm, pub); err != nil || n != 3 {
		t.Fatalf("bytes verifier on a genuine snapshot: n=%d err=%v", n, err)
	}
	if _, err := VerifyEd25519Bytes(trail, nil, pub); !errors.Is(err, ErrTamper) {
		t.Fatalf("snapshot without its .hwm must be tamper, got %v", err)
	}
	lines := bytes.SplitAfter(trail, []byte("\n"))
	if _, err := VerifyEd25519Bytes(bytes.Join(lines[:2], nil), hwm, pub); !errors.Is(err, ErrTamper) {
		t.Fatalf("truncated snapshot must be tamper, got %v", err)
	}
	mut := bytes.Replace(trail, []byte(`"decision":"deny"`), []byte(`"decision":"allow"`), 1)
	if _, err := VerifyEd25519Bytes(mut, hwm, pub); !errors.Is(err, ErrTamper) {
		t.Fatalf("mutated snapshot must be tamper, got %v", err)
	}
	if _, err := VerifyEd25519Bytes(trail, []byte("{not json"), pub); err == nil {
		t.Fatal("corrupt .hwm bytes must fail")
	}
}
