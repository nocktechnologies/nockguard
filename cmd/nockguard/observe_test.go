package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/policy"
	"github.com/nocktechnologies/nockguard/internal/proxy"
	"golang.org/x/sys/unix"
)

// TestObserveSetupSignsTrailAndReusesKey is the core proof: zero-config observe
// allows every tool, writes a signed audit trail through the REAL gate, and
// reuses one persisted key across runs so the signed trail's verify-on-open never
// trips a false tamper. On pre-change code this file does not build (observeSetup
// does not exist) — that is the RED; GREEN is this test passing.
func TestObserveSetupSignsTrailAndReusesKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// No explicit per-agent key env: exercise the persisted-key path.
	t.Setenv(policy.AgentKeyEnvName(defaultObserveAgent), "")

	engine, auditor, auditPath, pubHex, err := observeSetup(defaultObserveAgent)
	if err != nil {
		t.Fatalf("observeSetup: %v", err)
	}

	// Observe = allow all, deny nothing — for the default agent and any unnamed
	// agent (the "default" fallback governs both).
	if !engine.Check(defaultObserveAgent, "any_tool") {
		t.Fatalf("observe engine denied a tool for %q; want allow-all", defaultObserveAgent)
	}
	if !engine.Check("some-other-agent", "whatever_tool") {
		t.Fatalf("observe engine denied a tool for an unnamed agent; want default allow-all")
	}

	// Drive one allowed tools/call through the SAME gate live traffic takes, wired
	// to the signing auditor.
	logger := log.New(io.Discard, "", 0)
	p := proxy.NewStdioProxy(nil, defaultObserveAgent, engine, nil, nil, auditor, nil, logger)
	forwarded, _, perr := p.Probe(toolCallLine("search_web", `{"q":"hello"}`))
	if perr != nil {
		t.Fatalf("probe errored: %v", perr)
	}
	if !forwarded {
		t.Fatalf("observe mode did not forward an allowed call; want allow-all")
	}
	if err := auditor.Close(); err != nil {
		t.Fatalf("close auditor: %v", err)
	}

	// The trail lives at the standard per-agent path and Ed25519-verifies with the
	// public key the banner prints.
	wantPath := policy.AgentAuditPath(filepath.Join(home, policy.DefaultAuditPath), defaultObserveAgent)
	if auditPath != wantPath {
		t.Fatalf("audit path = %q, want %q", auditPath, wantPath)
	}
	pub, err := audit.PublicKeyFromHex(pubHex)
	if err != nil {
		t.Fatalf("pub key from hex: %v", err)
	}
	n, err := audit.VerifyEd25519(auditPath, pub)
	if err != nil {
		t.Fatalf("signed trail failed verification: %v", err)
	}
	if n < 1 {
		t.Fatalf("signed trail has %d entries, want >= 1 (the allowed call)", n)
	}
	keyDirInfo, err := os.Stat(filepath.Join(home, ".nockguard", "keys"))
	if err != nil {
		t.Fatalf("stat observe key directory: %v", err)
	}
	if perm := keyDirInfo.Mode().Perm(); perm != 0o700 {
		t.Fatalf("observe key directory permissions = %o, want 700", perm)
	}
	keyInfo, err := os.Stat(filepath.Join(home, ".nockguard", "keys", defaultObserveAgent+".ed25519"))
	if err != nil {
		t.Fatalf("stat observe key file: %v", err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0o600 {
		t.Fatalf("observe key file permissions = %o, want 600", perm)
	}

	// Second run in the same HOME must reuse the SAME key, and must open the
	// existing signed trail without a verify-on-open failure.
	_, auditor2, _, pubHex2, err := observeSetup(defaultObserveAgent)
	if err != nil {
		t.Fatalf("second observeSetup (append to existing signed trail): %v", err)
	}
	if err := auditor2.Close(); err != nil {
		t.Fatalf("close auditor2: %v", err)
	}
	if pubHex2 != pubHex {
		t.Fatalf("second run produced a different key: %q != %q", pubHex2, pubHex)
	}
}

// TestObserveSetupHonorsExplicitPerAgentKeyEnv proves an explicitly-set per-agent
// signing key (e.g. from `nockguard keygen --agent <name>`) is used instead of a
// generated file, so a user on the documented flow stays on one key.
func TestObserveSetupHonorsExplicitPerAgentKeyEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Generate a key at runtime (no literal key material in the test source) and
	// export it as the per-agent signing env var.
	privSeedHex, pubHex := freshEd25519(t)
	t.Setenv(policy.AgentKeyEnvName(defaultObserveAgent), privSeedHex)

	_, auditor, _, gotPubHex, err := observeSetup(defaultObserveAgent)
	if err != nil {
		t.Fatalf("observeSetup: %v", err)
	}
	if err := auditor.Close(); err != nil {
		t.Fatalf("close auditor: %v", err)
	}
	if gotPubHex != pubHex {
		t.Fatalf("observeSetup ignored the explicit per-agent key: pub %q != %q", gotPubHex, pubHex)
	}
	// No key file should have been written when the env key is honored.
	if _, statErr := os.Stat(filepath.Join(home, ".nockguard", "keys", defaultObserveAgent+".ed25519")); !os.IsNotExist(statErr) {
		t.Fatalf("a key file was persisted despite an explicit env key (stat err = %v)", statErr)
	}
}

func TestObserveSetupRejectsInvalidAgentBeforeWriting(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	outside := filepath.Join(home, "outside")
	agent := filepath.Join("..", "..", "outside")

	if _, _, _, _, err := observeSetup(agent); err == nil {
		t.Fatal("observeSetup accepted a path-traversing agent name")
	}
	if _, err := os.Stat(outside + ".ed25519"); !os.IsNotExist(err) {
		t.Fatalf("invalid agent wrote outside the key directory (stat err = %v)", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".nockguard")); !os.IsNotExist(err) {
		t.Fatalf("invalid agent created nockguard state before rejection (stat err = %v)", err)
	}
}

func TestEnsureObserveKeyConcurrentFirstStart(t *testing.T) {
	home := t.TempDir()
	const starters = 16

	pubs := make(chan string, starters)
	errs := make(chan error, starters)
	var wg sync.WaitGroup
	for range starters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, pub, err := ensureObserveKey(home, defaultObserveAgent)
			if err != nil {
				errs <- err
				return
			}
			pubs <- hex.EncodeToString(pub)
		}()
	}
	wg.Wait()
	close(errs)
	close(pubs)

	for err := range errs {
		t.Errorf("concurrent ensureObserveKey: %v", err)
	}
	var want string
	for got := range pubs {
		if want == "" {
			want = got
		} else if got != want {
			t.Errorf("concurrent starters used different keys: got %q, want %q", got, want)
		}
	}
	seedPath := filepath.Join(home, ".nockguard", "keys", defaultObserveAgent+".ed25519")
	seed, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatalf("read published seed: %v", err)
	}
	if _, _, err := loadSeedHex(seedPath, string(seed)); err != nil {
		t.Fatalf("published seed is incomplete or invalid: %v", err)
	}
}

func TestOpenOrCreateObserveDirExistingDirValidatesAndSyncsParent(t *testing.T) {
	parentPath := t.TempDir()
	parent, err := os.Open(parentPath)
	if err != nil {
		t.Fatalf("open parent: %v", err)
	}
	defer parent.Close()
	if err := os.Mkdir(filepath.Join(parentPath, "keys"), 0o700); err != nil {
		t.Fatalf("pre-create key dir: %v", err)
	}

	syncCalls := 0
	dir, err := openOrCreateObserveDir(int(parent.Fd()), "keys", 0o700, func(fd int) error {
		if fd != int(parent.Fd()) {
			t.Fatalf("sync parent fd = %d, want %d", fd, parent.Fd())
		}
		syncCalls++ // The callback runs only after the no-follow descriptor validates.
		return unix.Fsync(fd)
	})
	if err != nil {
		t.Fatalf("open pre-existing key dir: %v", err)
	}
	defer dir.Close()
	if syncCalls != 1 {
		t.Fatalf("parent sync calls = %d, want 1 after Mkdirat EEXIST", syncCalls)
	}
}

func TestEnsureObserveKeyAcceptsSetgidCreatedDirs(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0o700|os.ModeSetgid); err != nil {
		t.Fatalf("set setgid home permissions: %v", err)
	}
	probe := filepath.Join(home, "setgid-probe")
	if err := os.Mkdir(probe, 0o700); err != nil {
		t.Fatalf("create setgid inheritance probe: %v", err)
	}
	info, err := os.Stat(probe)
	if err != nil {
		t.Fatalf("stat setgid inheritance probe: %v", err)
	}
	if info.Mode()&os.ModeSetgid == 0 {
		t.Skip("filesystem does not inherit setgid on new directories")
	}
	if err := os.Remove(probe); err != nil {
		t.Fatalf("remove setgid inheritance probe: %v", err)
	}

	if _, _, err := ensureObserveKey(home, defaultObserveAgent); err != nil {
		t.Fatalf("ensureObserveKey with setgid parent: %v", err)
	}
	info, err = os.Stat(filepath.Join(home, ".nockguard"))
	if err != nil {
		t.Fatalf("stat created nockguard dir: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("created nockguard dir permissions = %o, want 700", got)
	}
}

func TestEnsureObserveKeyAcceptsExistingNockguardDirWithoutGroupOrOtherWrite(t *testing.T) {
	home := t.TempDir()
	nockguardDir := filepath.Join(home, ".nockguard")
	if err := os.Mkdir(nockguardDir, 0o755); err != nil {
		t.Fatalf("create existing nockguard dir: %v", err)
	}
	if err := os.Chmod(nockguardDir, 0o755); err != nil {
		t.Fatalf("set existing nockguard dir permissions: %v", err)
	}

	if _, _, err := ensureObserveKey(home, defaultObserveAgent); err != nil {
		t.Fatalf("ensureObserveKey with existing nockguard dir: %v", err)
	}
	info, err := os.Stat(nockguardDir)
	if err != nil {
		t.Fatalf("stat existing nockguard dir: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("existing nockguard dir permissions = %o, want 755", got)
	}
}

func TestEnsureObserveKeyRejectsGroupWritableNockguardDir(t *testing.T) {
	home := t.TempDir()
	nockguardDir := filepath.Join(home, ".nockguard")
	if err := os.Mkdir(nockguardDir, 0o700); err != nil {
		t.Fatalf("create group-writable nockguard dir: %v", err)
	}
	if err := os.Chmod(nockguardDir, 0o770); err != nil {
		t.Fatalf("set group-writable nockguard dir permissions: %v", err)
	}

	if _, _, err := ensureObserveKey(home, defaultObserveAgent); err == nil {
		t.Fatal("ensureObserveKey accepted a group-writable nockguard dir")
	} else if !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("ensureObserveKey error = %v, want permissions refusal", err)
	}
}

func TestEnsureObserveKeyRejectsForeignOwnedNockguardDir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create a foreign-owned directory")
	}

	home := t.TempDir()
	nockguardDir := filepath.Join(home, ".nockguard")
	if err := os.Mkdir(nockguardDir, 0o700); err != nil {
		t.Fatalf("create nockguard dir: %v", err)
	}
	if err := os.Chown(nockguardDir, 1, -1); err != nil {
		t.Fatalf("make nockguard dir foreign-owned: %v", err)
	}

	if _, _, err := ensureObserveKey(home, defaultObserveAgent); err == nil {
		t.Fatal("ensureObserveKey accepted a foreign-owned nockguard dir")
	} else if !strings.Contains(err.Error(), "owner uid") {
		t.Fatalf("ensureObserveKey error = %v, want owner refusal", err)
	}
}

func TestEnsureObserveKeyTightensReadOnlyExcessKeyDirPermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0o750, 0o755} {
		t.Run(mode.String(), func(t *testing.T) {
			home := t.TempDir()
			nockguardDir := filepath.Join(home, ".nockguard")
			keyDir := filepath.Join(nockguardDir, "keys")
			if err := os.Mkdir(nockguardDir, 0o700); err != nil {
				t.Fatalf("create nockguard dir: %v", err)
			}
			if err := os.Mkdir(keyDir, 0o700); err != nil {
				t.Fatalf("create key dir: %v", err)
			}
			if err := os.Chmod(keyDir, mode); err != nil {
				t.Fatalf("set key dir permissions: %v", err)
			}

			if _, _, err := ensureObserveKey(home, defaultObserveAgent); err != nil {
				t.Fatalf("ensureObserveKey with %o key dir: %v", mode, err)
			}
			info, err := os.Stat(keyDir)
			if err != nil {
				t.Fatalf("stat key dir: %v", err)
			}
			if got := info.Mode().Perm(); got != 0o700 {
				t.Fatalf("key dir permissions = %o, want 700", got)
			}
		})
	}
}

func TestEnsureObserveKeyRejectsWritableExistingKeyDirWithoutReadingKey(t *testing.T) {
	for _, mode := range []os.FileMode{0o770, 0o777} {
		t.Run(mode.String(), func(t *testing.T) {
			home := t.TempDir()
			keyDir := filepath.Join(home, ".nockguard", "keys")
			if err := os.MkdirAll(keyDir, 0o700); err != nil {
				t.Fatal(err)
			}
			keyPath := filepath.Join(keyDir, defaultObserveAgent+".ed25519")
			if err := os.WriteFile(keyPath, []byte("planted-invalid-seed"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(keyDir, mode); err != nil {
				t.Fatal(err)
			}

			_, _, err := ensureObserveKey(home, defaultObserveAgent)
			if err == nil {
				t.Fatalf("ensureObserveKey accepted a pre-existing %o key dir", mode)
			}
			if !strings.Contains(err.Error(), "group/other writable") || strings.Contains(err.Error(), "parsing persisted key") {
				t.Fatalf("ensureObserveKey error = %v, want directory refusal before key read", err)
			}
			info, statErr := os.Stat(keyDir)
			if statErr != nil {
				t.Fatal(statErr)
			}
			if got := info.Mode().Perm(); got != mode {
				t.Fatalf("refused key dir permissions = %o, want unchanged %o", got, mode)
			}
		})
	}
}

func TestEnsureObserveKeyRejectsGroupOrOtherAccessibleExistingKeyFileBeforeParsing(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o644, 0o604, 0o620} {
		t.Run(mode.String(), func(t *testing.T) {
			home := t.TempDir()
			keyDir := filepath.Join(home, ".nockguard", "keys")
			if err := os.MkdirAll(keyDir, 0o700); err != nil {
				t.Fatal(err)
			}
			keyPath := filepath.Join(keyDir, defaultObserveAgent+".ed25519")
			if err := os.WriteFile(keyPath, []byte("planted-invalid-seed"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(keyPath, mode); err != nil {
				t.Fatal(err)
			}

			if _, _, err := ensureObserveKey(home, defaultObserveAgent); err == nil {
				t.Fatalf("ensureObserveKey accepted a pre-existing %o key file", mode)
			} else if !strings.Contains(err.Error(), "group/other readable or writable") || !strings.Contains(err.Error(), "inspect and recreate the key file") || strings.Contains(err.Error(), "parsing persisted key") {
				t.Fatalf("ensureObserveKey error = %v, want key-file permission refusal before parsing", err)
			}
		})
	}
}

func TestEnsureObserveKeyAcceptsPrivateExistingKeyFileModes(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o400} {
		t.Run(mode.String(), func(t *testing.T) {
			home := t.TempDir()
			keyDir := filepath.Join(home, ".nockguard", "keys")
			if err := os.MkdirAll(keyDir, 0o700); err != nil {
				t.Fatal(err)
			}
			seedHex, pubHex := freshEd25519(t)
			keyPath := filepath.Join(keyDir, defaultObserveAgent+".ed25519")
			if err := os.WriteFile(keyPath, []byte(seedHex), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(keyPath, mode); err != nil {
				t.Fatal(err)
			}

			_, pub, err := ensureObserveKey(home, defaultObserveAgent)
			if err != nil {
				t.Fatalf("ensureObserveKey with %o key file: %v", mode, err)
			}
			if got := hex.EncodeToString(pub); got != pubHex {
				t.Fatalf("ensureObserveKey loaded pub %q, want %q", got, pubHex)
			}
		})
	}
}

func TestEnsureObserveKeyRejectsForeignOwnedKeyDir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create a foreign-owned directory")
	}

	home := t.TempDir()
	keyDir := filepath.Join(home, ".nockguard", "keys")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(keyDir, 1, -1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ensureObserveKey(home, defaultObserveAgent); err == nil {
		t.Fatal("ensureObserveKey accepted a foreign-owned key dir")
	} else if !strings.Contains(err.Error(), "owner uid") {
		t.Fatalf("ensureObserveKey error = %v, want owner refusal", err)
	}
}

func TestEnsureObserveKeyRejectsForeignOwnedKeyFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create a foreign-owned file")
	}

	home := t.TempDir()
	keyDir := filepath.Join(home, ".nockguard", "keys")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	seedHex, _ := freshEd25519(t)
	keyPath := filepath.Join(keyDir, defaultObserveAgent+".ed25519")
	if err := os.WriteFile(keyPath, []byte(seedHex), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(keyPath, 1, -1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ensureObserveKey(home, defaultObserveAgent); err == nil {
		t.Fatal("ensureObserveKey accepted a foreign-owned key file")
	} else if !strings.Contains(err.Error(), "owner uid") {
		t.Fatalf("ensureObserveKey error = %v, want owner refusal", err)
	}
}

func TestEnsureObserveKeyRejectsSymlinkedPaths(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, home, target string)
	}{
		{
			name: "nockguard state dir",
			setup: func(t *testing.T, home, target string) {
				t.Helper()
				if err := os.Symlink(target, filepath.Join(home, ".nockguard")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "keyDir",
			setup: func(t *testing.T, home, target string) {
				t.Helper()
				if err := os.Mkdir(filepath.Join(home, ".nockguard"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(home, ".nockguard", "keys")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "private key",
			setup: func(t *testing.T, home, target string) {
				t.Helper()
				keyDir := filepath.Join(home, ".nockguard", "keys")
				if err := os.MkdirAll(keyDir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(target, "seed"), filepath.Join(keyDir, defaultObserveAgent+".ed25519")); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home, target := t.TempDir(), t.TempDir()
			tt.setup(t, home, target)

			if _, _, err := ensureObserveKey(home, defaultObserveAgent); err == nil {
				t.Fatal("ensureObserveKey accepted a symlinked state path")
			} else if !strings.Contains(err.Error(), "symlink") {
				t.Fatalf("ensureObserveKey error = %v, want a symlink refusal", err)
			}
			if entries, err := os.ReadDir(target); err != nil {
				t.Fatal(err)
			} else if len(entries) != 0 {
				t.Fatalf("symlink target received key state: %v", entries)
			}
		})
	}
}

// TestProxyDefaultPolicyPresentIsLoadedNotObserved proves a policy file present at
// the DEFAULT path is loaded (and its errors surfaced), never silently replaced
// by observe mode. Constraint: do NOT change behavior when a policy file exists.
func TestProxyDefaultPolicyPresentIsLoadedNotObserved(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	policyDir := filepath.Join(home, ".nockguard")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Syntactically invalid YAML: proves Load ran, rather than observe bypassing it.
	if err := os.WriteFile(filepath.Join(policyDir, "policy.yaml"), []byte("agents: [unterminated"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := runCommandForTest(t, "proxy", "--upstream", "true", "--agent", "coder")
	if code != 1 {
		t.Fatalf("exit = %d, want 1\nstderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "error loading policy") {
		t.Fatalf("stderr should report a load error (present default policy loaded), got:\n%s", stderr)
	}
}

// TestProxyExplicitMissingPolicyStillErrors proves an explicit --policy to a
// missing file still errors — it is never reinterpreted as zero-config observe.
// Constraint: do NOT change behavior when a policy file IS provided.
func TestProxyExplicitMissingPolicyStillErrors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	missing := filepath.Join(home, "does-not-exist.yaml")

	code, _, stderr := runCommandForTest(t, "proxy", "--upstream", "true", "--agent", "coder", "--policy", missing)
	if code != 1 {
		t.Fatalf("exit = %d, want 1\nstderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "error loading policy") {
		t.Fatalf("explicit --policy to a missing file must still error, got:\n%s", stderr)
	}
}

// TestProxyDanglingPolicyFlagDoesNotObserve proves that naming --policy without a
// value still means "the user named a policy": it must load-or-error, never be
// reinterpreted as zero-config observe (allow-all). Guards the invariant that an
// explicit --policy is never bypassed.
func TestProxyDanglingPolicyFlagDoesNotObserve(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home) // no policy file anywhere

	code, _, stderr := runCommandForTest(t, "proxy", "--upstream", "true", "--agent", "coder", "--policy")
	if code != 1 {
		t.Fatalf("exit = %d, want 1\nstderr:\n%s", code, stderr)
	}
	if strings.Contains(stderr, "OBSERVE MODE") {
		t.Fatalf("dangling --policy must not enter observe mode, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "error loading policy") {
		t.Fatalf("dangling --policy must load-or-error, got:\n%s", stderr)
	}
}

// TestProxyPolicyPresentRequiresAgent proves the existing "--agent is required"
// error is preserved whenever a policy file governs the run.
func TestProxyPolicyPresentRequiresAgent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	policyDir := filepath.Join(home, ".nockguard")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "policy.yaml"), []byte("agents:\n  coder:\n    mode: allow\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := runCommandForTest(t, "proxy", "--upstream", "true")
	if code != 1 {
		t.Fatalf("exit = %d, want 1\nstderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "--agent is required") {
		t.Fatalf("policy present + no --agent must still error, got:\n%s", stderr)
	}
}

// TestProxyZeroConfigObserveEndToEnd drives the real `proxy --upstream <x>`
// command with no policy file: it must start in observe mode (banner on stderr)
// and create a signed audit trail. stdin is fed EOF so the proxy's agent loop
// returns promptly and the upstream exits.
func TestProxyZeroConfigObserveEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("cat"); err != nil {
		t.Skip("cat not available")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(policy.AgentKeyEnvName(defaultObserveAgent), "")

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = stdinW.Close() // immediate EOF for the agent->upstream loop
	oldStdin := os.Stdin
	os.Stdin = stdinR
	defer func() { os.Stdin = oldStdin; _ = stdinR.Close() }()

	code, _, stderr := runCommandForTest(t, "proxy", "--upstream", "cat")
	if code != 0 {
		t.Fatalf("zero-config proxy exit = %d, want 0\nstderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "OBSERVE MODE") {
		t.Fatalf("stderr should announce observe mode, got:\n%s", stderr)
	}

	auditPath := policy.AgentAuditPath(filepath.Join(home, policy.DefaultAuditPath), defaultObserveAgent)
	pubBytes, err := os.ReadFile(filepath.Join(home, ".nockguard", "keys", defaultObserveAgent+".ed25519.pub"))
	if err != nil {
		t.Fatalf("read persisted pub key: %v", err)
	}
	pub, err := audit.PublicKeyFromHex(strings.TrimSpace(string(pubBytes)))
	if err != nil {
		t.Fatalf("pub from hex: %v", err)
	}
	if _, err := audit.VerifyEd25519(auditPath, pub); err != nil {
		t.Fatalf("signed observe trail failed verification: %v", err)
	}
}

// freshEd25519 generates an Ed25519 keypair at runtime and returns the private
// seed hex and public key hex, so no key literal ever appears in the source
// (gitleaks scans this repo's history).
func freshEd25519(t *testing.T) (privSeedHex, pubHex string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return hex.EncodeToString(priv.Seed()), hex.EncodeToString(pub)
}
