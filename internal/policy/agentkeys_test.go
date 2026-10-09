package policy

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"golang.org/x/sys/unix"
)

func seededHome(t *testing.T, agent string, seedMode os.FileMode) (home string, seed ed25519.PrivateKey) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(AgentKeyEnvName(agent), "")
	t.Setenv(AgentPubKeyEnvName(agent), "")
	if err := os.MkdirAll(AgentKeyDir(home), 0o700); err != nil {
		t.Fatal(err)
	}
	_, seed, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p := AgentSeedPath(home, agent)
	if err := os.WriteFile(p, []byte(hex.EncodeToString(seed.Seed())), seedMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, seedMode); err != nil {
		t.Fatal(err)
	}
	return home, seed
}

func TestResolveAgentSeedFileAndEnvPrecedence(t *testing.T) {
	_, seed := seededHome(t, "kit", 0o600)
	fileHex := hex.EncodeToString(seed.Seed())

	got, err := ResolveAgentSeed("kit")
	if err != nil || got != fileHex {
		t.Fatalf("file source: got (match=%v, %v)", got == fileHex, err)
	}

	t.Setenv(AgentKeyEnvName("kit"), "envwins")
	got, err = ResolveAgentSeed("kit")
	if err != nil || got != "envwins" {
		t.Fatalf("env must beat file: got (%q, %v)", got, err)
	}
}

func TestResolveAgentSeedAbsentIsNotAnError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(AgentKeyEnvName("kit"), "")
	if got, err := ResolveAgentSeed("kit"); got != "" || err != nil {
		t.Fatalf("absent: got (%q, %v), want empty", got, err)
	}
}

func TestResolveAgentSeedRefusesUnsafeFiles(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o604, 0o660, 0o644, 0o666} {
		t.Run(mode.String(), func(t *testing.T) {
			_, seed := seededHome(t, "kit", mode)
			got, err := ResolveAgentSeed("kit")
			if err == nil || got != "" {
				t.Fatalf("mode %o seed accepted: (%q, %v)", mode, got, err)
			}
			if strings.Contains(err.Error(), hex.EncodeToString(seed.Seed())) {
				t.Errorf("error should not carry key material: %v", err)
			}
		})
	}

	t.Run("symlink", func(t *testing.T) {
		home, _ := seededHome(t, "kit", 0o600)
		real := filepath.Join(t.TempDir(), "real")
		if err := os.Rename(AgentSeedPath(home, "kit"), real); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, AgentSeedPath(home, "kit")); err != nil {
			t.Fatal(err)
		}
		if got, err := ResolveAgentSeed("kit"); err == nil || got != "" {
			t.Fatalf("symlinked seed accepted: (%q, %v)", got, err)
		}
	})

	t.Run("directory", func(t *testing.T) {
		home, _ := seededHome(t, "kit", 0o600)
		p := AgentSeedPath(home, "kit")
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if got, err := ResolveAgentSeed("kit"); err == nil || got != "" {
			t.Fatalf("directory-as-seed accepted: (%q, %v)", got, err)
		}
	})

	t.Run("group-writable key dir", func(t *testing.T) {
		home, _ := seededHome(t, "kit", 0o600)
		if err := os.Chmod(AgentKeyDir(home), 0o770); err != nil {
			t.Fatal(err)
		}
		if got, err := ResolveAgentSeed("kit"); err == nil || got != "" {
			t.Fatalf("group-writable keys dir accepted: (%q, %v)", got, err)
		}
	})
}

func TestAuditorForSignsWithSeedFile(t *testing.T) {
	home, seed := seededHome(t, "kit", 0o600)
	logDir := t.TempDir()
	path := writePolicy(t, "audit:\n  enabled: true\n  path: "+filepath.Join(logDir, "audit.jsonl")+"\nagents:\n  kit:\n    allow: [\"*\"]\n")
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := eng.AuditorFor("kit")
	if err != nil {
		t.Fatalf("AuditorFor with seed file: %v", err)
	}
	if err := a.Record(audit.Event{Agent: "kit", Tool: "Read", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	a.Close()
	trail := AgentAuditPath(filepath.Join(logDir, "audit.jsonl"), "kit")
	if _, err := audit.VerifyEd25519(trail, seed.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("trail is not signed by the seed file's key: %v", err)
	}

	// An unsafe seed file must fail closed, not fall back to an unsigned trail.
	if err := os.Chmod(AgentSeedPath(home, "kit"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.AuditorFor("kit"); err == nil {
		t.Fatal("AuditorFor accepted a group-readable seed file")
	}
}

func TestAuditorForEnvSeedBeatsSeedFile(t *testing.T) {
	seededHome(t, "kit", 0o600)
	_, envPriv, _ := ed25519.GenerateKey(nil)
	t.Setenv(AgentKeyEnvName("kit"), hex.EncodeToString(envPriv.Seed()))
	logDir := t.TempDir()
	path := writePolicy(t, "audit:\n  enabled: true\n  path: "+filepath.Join(logDir, "audit.jsonl")+"\nagents:\n  kit:\n    allow: [\"*\"]\n")
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := eng.AuditorFor("kit")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Record(audit.Event{Agent: "kit", Tool: "Read", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	a.Close()
	trail := AgentAuditPath(filepath.Join(logDir, "audit.jsonl"), "kit")
	if _, err := audit.VerifyEd25519(trail, envPriv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("env key must sign when both are present: %v", err)
	}
}

func TestResolveAgentSeedHomeUnknownMeansNoKeyFile(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv(AgentKeyEnvName("kit"), "")
	if v, err := ResolveAgentSeed("kit"); v != "" || err != nil {
		t.Fatalf("no home dir: got (%q, %v), want no key and no error", v, err)
	}
	t.Setenv(AgentKeyEnvName("kit"), "fromenv")
	if v, err := ResolveAgentSeed("kit"); v != "fromenv" || err != nil {
		t.Fatalf("env must still work without a home dir: got (%q, %v)", v, err)
	}
}

func TestAuditorForWithoutHomeFallsBackToPolicyWide(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv(AgentKeyEnvName("kit"), "")
	trail := filepath.Join(t.TempDir(), "audit.jsonl")
	eng, err := Load(writePolicy(t, "audit:\n  enabled: true\n  path: "+trail+"\nagents:\n  kit:\n    allow: [\"*\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := eng.AuditorFor("kit")
	if err != nil {
		t.Fatalf("AuditorFor must not fail startup when HOME is unset and no per-agent key is wanted: %v", err)
	}
	if err := a.Record(audit.Event{Agent: "kit", Tool: "Read", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	a.Close()
	if _, err := os.Stat(trail); err != nil {
		t.Errorf("policy-wide trail %s should be written: %v", trail, err)
	}
	if _, err := os.Stat(AgentAuditPath(trail, "kit")); err == nil {
		t.Error("no per-agent key: trail must not move to the per-agent path")
	}
}

func TestResolveAgentKeyEmptyFileIsAnError(t *testing.T) {
	for _, content := range []string{"", "  \n\t\n"} {
		home, _ := seededHome(t, "kit", 0o600)
		if err := os.WriteFile(AgentSeedPath(home, "kit"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := ResolveAgentSeed("kit")
		if err == nil || got != "" || !strings.Contains(err.Error(), "empty") || !strings.Contains(err.Error(), AgentSeedPath(home, "kit")) {
			t.Errorf("empty seed %q: got (%q, %v), want an error naming the path and 'empty'", content, got, err)
		}

		if err := os.WriteFile(AgentPubPath(home, "kit"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if got, _, err := ResolveAgentPub("kit"); err == nil || got != "" || !strings.Contains(err.Error(), "empty") {
			t.Errorf("empty pub %q: got (%q, %v), want an 'empty' error", content, got, err)
		}
	}
}

func TestAuditorForEmptySeedFileFailsClosed(t *testing.T) {
	home, _ := seededHome(t, "kit", 0o600)
	if err := os.WriteFile(AgentSeedPath(home, "kit"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := Load(writePolicy(t, "audit:\n  enabled: true\n  path: "+filepath.Join(t.TempDir(), "audit.jsonl")+"\nagents:\n  kit:\n    allow: [\"*\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.AuditorFor("kit"); err == nil {
		t.Fatal("an empty seed file must not fall back to the weaker policy-wide signing")
	}
}

func TestResolveAgentKeyFIFODoesNotBlock(t *testing.T) {
	for name, secret := range map[string]bool{"seed": true, "pub": false} {
		t.Run(name, func(t *testing.T) {
			home, _ := seededHome(t, "kit", 0o600)
			p := AgentSeedPath(home, "kit")
			if !secret {
				p = AgentPubPath(home, "kit")
			}
			os.Remove(p)
			if err := unix.Mkfifo(p, 0o600); err != nil {
				t.Fatal(err)
			}
			// Opening a FIFO read-only blocks until a writer appears; release it on exit
			// so a regression fails the test instead of leaking a hung goroutine.
			t.Cleanup(func() {
				if fd, err := unix.Open(p, unix.O_RDWR, 0); err == nil {
					unix.Close(fd)
				}
			})
			done := make(chan error, 1)
			go func() {
				var err error
				if secret {
					_, err = ResolveAgentSeed("kit")
				} else {
					_, _, err = ResolveAgentPub("kit")
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "not a regular file") {
					t.Fatalf("FIFO key file: got %v, want a not-a-regular-file refusal", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("reading a FIFO key file blocked")
			}
		})
	}
}

func TestResolveAgentPubReportsSource(t *testing.T) {
	home, _ := seededHome(t, "kit", 0o600)
	if err := os.WriteFile(AgentPubPath(home, "kit"), []byte("filepub\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if k, src, err := ResolveAgentPub("kit"); err != nil || k != "filepub" || src != AgentPubPath(home, "kit") {
		t.Fatalf("file: got (%q, %q, %v)", k, src, err)
	}
	t.Setenv(AgentPubKeyEnvName("kit"), "envpub")
	if k, src, err := ResolveAgentPub("kit"); err != nil || k != "envpub" || src != AgentPubKeyEnvName("kit") {
		t.Fatalf("env: got (%q, %q, %v)", k, src, err)
	}
}

func TestAuditorForPolicySigningKeyBeatsSeedFile(t *testing.T) {
	seededHome(t, "kit", 0o600) // a seed file, as observe mode would have left
	_, polPriv, _ := ed25519.GenerateKey(nil)
	t.Setenv("TEST_POLICY_SIGNING_KEY", hex.EncodeToString(polPriv.Seed()))
	trail := filepath.Join(t.TempDir(), "audit.jsonl")
	eng, err := Load(writePolicy(t, "audit:\n  enabled: true\n  path: "+trail+"\n  sign_ed25519_key_env: TEST_POLICY_SIGNING_KEY\nagents:\n  kit:\n    allow: [\"*\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := eng.AuditorFor("kit")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Record(audit.Event{Agent: "kit", Tool: "Read", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	a.Close()
	if _, err := audit.VerifyEd25519(trail, polPriv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("explicit policy key must sign at the policy trail path, not the seed file's key: %v", err)
	}

	// The per-agent env var still outranks the explicit policy key.
	_, envPriv, _ := ed25519.GenerateKey(nil)
	t.Setenv(AgentKeyEnvName("kit"), hex.EncodeToString(envPriv.Seed()))
	a, err = eng.AuditorFor("kit")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Record(audit.Event{Agent: "kit", Tool: "Read", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	a.Close()
	if _, err := audit.VerifyEd25519(AgentAuditPath(trail, "kit"), envPriv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("per-agent env key must beat the policy key: %v", err)
	}
}
