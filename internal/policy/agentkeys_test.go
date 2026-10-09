package policy

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nockguard/internal/audit"
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

func TestResolveAgentSeedErrorsWhenHomeUnknown(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv(AgentKeyEnvName("kit"), "")
	if v, err := ResolveAgentSeed("kit"); err == nil {
		t.Fatalf("want an error when no home dir is available, got %q", v)
	}
}
