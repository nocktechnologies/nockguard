package audit

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckpointLagRecovery(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("checkpoint-recovery-test")
	for _, tc := range []struct {
		name   string
		opt    Option
		verify func(string) (int, error)
	}{
		{"hmac", WithSigningKey(key), func(path string) (int, error) { return Verify(path, key) }},
		{"ed25519", WithEd25519Key(priv), func(path string) (int, error) { return VerifyEd25519(path, pub) }},
	} {
		for _, restart := range []bool{false, true} {
			t.Run(tc.name+map[bool]string{false: "/live-writer", true: "/restart"}[restart], func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "audit.jsonl")
				a, err := New(path, tc.opt)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = a.Close() })
				record := func() {
					t.Helper()
					if err := a.Record(Event{Agent: "kit", Tool: "safe", Decision: "allow"}); err != nil {
						t.Fatal(err)
					}
				}
				record()
				checkpoint, err := os.ReadFile(path + hwmSuffix)
				if err != nil {
					t.Fatal(err)
				}
				record()
				record()
				// Model successful appends followed by failed checkpoint replacements.
				if err := os.WriteFile(path+hwmSuffix, checkpoint, 0600); err != nil {
					t.Fatal(err)
				}
				if n, err := tc.verify(path); err != nil || n != 3 {
					t.Fatalf("lagged trail: n=%d err=%v", n, err)
				}
				if restart {
					if err := a.Close(); err != nil {
						t.Fatal(err)
					}
					a, err = New(path, tc.opt)
					if err != nil {
						t.Fatal(err)
					}
				}
				record()
				if n, err := tc.verify(path); err != nil || n != 4 {
					t.Fatalf("recovered trail: n=%d err=%v", n, err)
				}
				hwm, err := readHighWaterMark(path + hwmSuffix)
				if err != nil || hwm.Count != 4 {
					t.Fatalf("checkpoint not caught up: %v %v", hwm, err)
				}
				truncateLastLine(t, path)
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := a.Record(Event{Agent: "kit"}); err == nil {
					t.Fatal("must not repair a truncated trail")
				}
				after, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if string(before) != string(after) {
					t.Fatal("failed recovery mutated trail")
				}
				// Neither an unsigned replacement tail nor a deleted checkpoint
				// can turn an existing trail back into a trusted empty one.
				if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path + hwmSuffix); err != nil {
					t.Fatal(err)
				}
				if err := a.Record(Event{Agent: "kit"}); err == nil {
					t.Fatal("unsigned tail with missing checkpoint accepted")
				}
			})
		}
	}
}
