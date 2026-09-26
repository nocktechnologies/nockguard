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
