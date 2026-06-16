package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"sync"
	"testing"
)

// TestConcurrentAuditorsKeepChainVerifiable reproduces the cross-process
// hash-chain fork that desynced Mira's live dogfood trail (false TAMPER at the
// second writer's entry).
//
// Two Auditors opened on the SAME path simulate two proxy PROCESSES: each seeds
// its chain from the file tail at New() and — before the fix — chained every
// subsequent entry off its own STALE in-memory prevSig. O_APPEND keeps the bytes
// of each line intact, but the two writers each link off the same seed, forking
// the single on-disk chain so Verify reports a false tamper. (flock coordinates
// separate open file descriptions even within one process, so two in-process
// Auditors are a faithful stand-in for two processes.)
//
// The chain MUST stay verifiable end to end under concurrent writers.
func TestConcurrentAuditorsKeepChainVerifiable(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hmacKey := []byte("concurrent-write-signing-key")

	cases := []struct {
		name   string
		opt    Option
		verify func(path string) (int, error)
	}{
		{
			name:   "hmac",
			opt:    WithSigningKey(hmacKey),
			verify: func(path string) (int, error) { return Verify(path, hmacKey) },
		},
		{
			name:   "ed25519",
			opt:    WithEd25519Key(priv),
			verify: func(path string) (int, error) { return VerifyEd25519(path, pub) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")

			// One initial entry so both auditors seed a non-empty tail — the
			// exact precondition that made the stale-seed fork inevitable.
			a0, err := New(path, tc.opt)
			if err != nil {
				t.Fatal(err)
			}
			if err := a0.Record(Event{Agent: "mira", Tool: "seed", Decision: "allow"}); err != nil {
				t.Fatal(err)
			}
			a0.Close()

			a, err := New(path, tc.opt)
			if err != nil {
				t.Fatal(err)
			}
			b, err := New(path, tc.opt)
			if err != nil {
				t.Fatal(err)
			}

			const perWriter = 30
			var wg sync.WaitGroup
			for _, au := range []*Auditor{a, b} {
				wg.Add(1)
				go func(au *Auditor) {
					defer wg.Done()
					for i := 0; i < perWriter; i++ {
						if err := au.Record(Event{Agent: "mira", Tool: "nockcc_nock_get", Decision: "allow"}); err != nil {
							t.Errorf("Record: %v", err)
						}
					}
				}(au)
			}
			wg.Wait()
			a.Close()
			b.Close()

			n, err := tc.verify(path)
			if err != nil {
				t.Fatalf("chain must stay verifiable under concurrent writers, got: %v", err)
			}
			if want := 1 + 2*perWriter; n != want {
				t.Errorf("expected %d verified entries, got %d", want, n)
			}
		})
	}
}
