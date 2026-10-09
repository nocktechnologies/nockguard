package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/policy"
)

func keygenHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func TestKeygenWritesKeyFilesAndKeepsSeedOffStdout(t *testing.T) {
	home := keygenHome(t)
	code, stdout, stderr := runCommandForTest(t, "keygen", "--agent", "kit")
	if code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	seedPath, pubPath := policy.AgentSeedPath(home, "kit"), policy.AgentPubPath(home, "kit")
	if got := fileMode(t, filepath.Dir(seedPath)); got != 0o700 {
		t.Errorf("key dir mode = %o, want 700", got)
	}
	if got := fileMode(t, seedPath); got != 0o600 {
		t.Errorf("seed mode = %o, want 600", got)
	}
	if got := fileMode(t, pubPath); got != 0o644 {
		t.Errorf("pub mode = %o, want 644", got)
	}
	seedHex, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(string(seedHex))
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("seed file is not a hex 32-byte seed: %v", err)
	}
	wantPub := hex.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if gotPub, _ := os.ReadFile(pubPath); string(gotPub) != wantPub {
		t.Errorf("pub file = %q, want %q", gotPub, wantPub)
	}
	for _, want := range []string{seedPath, pubPath, wantPub} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout should show %q, got:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout+stderr, string(seedHex)) || strings.Contains(stdout+stderr, "_ED25519_KEY=") {
		t.Fatalf("seed leaked to output:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}

func TestKeygenWithoutAgentUsesDefaultName(t *testing.T) {
	home := keygenHome(t)
	if code, stdout, stderr := runCommandForTest(t, "keygen"); code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	for _, p := range []string{policy.AgentSeedPath(home, "default"), policy.AgentPubPath(home, "default")} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected %s: %v", p, err)
		}
	}
}

func TestKeygenRefusesOverwriteUnlessForce(t *testing.T) {
	home := keygenHome(t)
	if code, _, stderr := runCommandForTest(t, "keygen", "--agent", "kit"); code != 0 {
		t.Fatalf("first keygen: %d %s", code, stderr)
	}
	seedPath, pubPath := policy.AgentSeedPath(home, "kit"), policy.AgentPubPath(home, "kit")
	origSeed, _ := os.ReadFile(seedPath)
	origPub, _ := os.ReadFile(pubPath)

	code, _, stderr := runCommandForTest(t, "keygen", "--agent", "kit")
	if code == 0 || !strings.Contains(stderr, "already exists") {
		t.Fatalf("second keygen exit %d, stderr %q; want refusal", code, stderr)
	}
	if s, _ := os.ReadFile(seedPath); string(s) != string(origSeed) {
		t.Fatal("seed was overwritten without --force")
	}
	if p, _ := os.ReadFile(pubPath); string(p) != string(origPub) {
		t.Fatal("pub was overwritten without --force")
	}

	code, stdout, stderr := runCommandForTest(t, "keygen", "--agent", "kit", "--force")
	if code != 0 {
		t.Fatalf("--force exit %d: %s", code, stderr)
	}
	if !strings.Contains(stderr, "no longer verify") {
		t.Errorf("--force should warn about old trails, got %q", stderr)
	}
	if s, _ := os.ReadFile(seedPath); string(s) == string(origSeed) {
		t.Error("--force did not replace the seed")
	}
	if got := fileMode(t, seedPath); got != 0o600 {
		t.Errorf("seed mode after --force = %o, want 600", got)
	}
	if strings.Contains(stdout, "ED25519_KEY=") {
		t.Errorf("seed leaked on stdout: %s", stdout)
	}
}

func TestKeygenRefusesSymlinks(t *testing.T) {
	for _, tc := range []struct{ name, link string }{
		{"seed", "kit.ed25519"},
		{"pub", "kit.pub"},
	} {
		for _, force := range []bool{false, true} {
			t.Run(tc.name, func(t *testing.T) {
				home := keygenHome(t)
				keyDir := policy.AgentKeyDir(home)
				if err := os.MkdirAll(keyDir, 0o700); err != nil {
					t.Fatal(err)
				}
				victim := filepath.Join(t.TempDir(), "victim")
				if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(victim, filepath.Join(keyDir, tc.link)); err != nil {
					t.Fatal(err)
				}
				args := []string{"keygen", "--agent", "kit"}
				if force {
					args = append(args, "--force")
				}
				code, _, stderr := runCommandForTest(t, args...)
				if code == 0 || !strings.Contains(stderr, "symlink") {
					t.Fatalf("exit %d stderr %q; want symlink refusal (force=%v)", code, stderr, force)
				}
				if b, _ := os.ReadFile(victim); string(b) != "untouched" {
					t.Fatalf("keygen wrote through the symlink: %q", b)
				}
			})
		}
	}

	t.Run("keys dir", func(t *testing.T) {
		home := keygenHome(t)
		real := filepath.Join(t.TempDir(), "elsewhere")
		if err := os.Mkdir(real, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(home, ".nockguard"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, policy.AgentKeyDir(home)); err != nil {
			t.Fatal(err)
		}
		if code, _, stderr := runCommandForTest(t, "keygen", "--agent", "kit", "--force"); code == 0 || !strings.Contains(stderr, "symlink") {
			t.Fatalf("exit %d stderr %q; want symlink refusal", code, stderr)
		}
		if entries, _ := os.ReadDir(real); len(entries) != 0 {
			t.Fatalf("keygen wrote through a symlinked keys dir: %v", entries)
		}
	})
}

func TestKeygenPrintEnvIsExplicitAndWritesNoFiles(t *testing.T) {
	home := keygenHome(t)
	code, stdout, stderr := runCommandForTest(t, "keygen", "--print-env", "--agent", "kit")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, want := range []string{"NOCKGUARD_AGENT_KIT_ED25519_KEY=", "NOCKGUARD_AGENT_KIT_ED25519_PUB="} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
	}
	if !strings.Contains(stderr, "secret") {
		t.Errorf("--print-env must warn the seed is secret, got %q", stderr)
	}
	if _, err := os.Stat(filepath.Join(home, ".nockguard")); !os.IsNotExist(err) {
		t.Errorf("--print-env should not write files (stat err = %v)", err)
	}

	code, stdout, _ = runCommandForTest(t, "keygen", "--print-env")
	if code != 0 || !strings.Contains(stdout, "NOCKGUARD_AUDIT_ED25519_KEY=") || !strings.Contains(stdout, "NOCKGUARD_AUDIT_ED25519_PUB=") {
		t.Fatalf("agent-less --print-env should keep the legacy names, got exit %d:\n%s", code, stdout)
	}
}

func TestKeygenRejectsUnknownFlag(t *testing.T) {
	keygenHome(t)
	if code, _, stderr := runCommandForTest(t, "keygen", "--print-evn"); code == 0 || !strings.Contains(stderr, "unknown flag") {
		t.Fatalf("exit %d stderr %q; want unknown-flag error", code, stderr)
	}
}

func TestVerifyAndEvidenceReadPubKeyFile(t *testing.T) {
	home := keygenHome(t)
	dir := t.TempDir()
	path, pubHex := writeEd25519Trail(t, dir, "kit")
	t.Setenv(policy.AgentPubKeyEnvName("kit"), "")

	if code, _, stderr := runCommandForTest(t, "verify", "--agent", "kit", "--audit-dir", dir); code != 1 || !strings.Contains(stderr, policy.AgentPubPath(home, "kit")) {
		t.Fatalf("no key anywhere: exit %d stderr %q; want 1 naming the pub file path", code, stderr)
	}

	if err := os.MkdirAll(policy.AgentKeyDir(home), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy.AgentPubPath(home, "kit"), []byte(pubHex+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for name, args := range map[string][]string{
		"verify":     {"verify", "--agent", "kit", "--audit-dir", dir},
		"verify all": {"verify", "--all", "--audit-dir", dir},
		"evidence":   {"evidence", "--framework", "soc2", "--agent", "kit", "--audit-dir", dir, "--format", "json"},
	} {
		if code, stdout, stderr := runCommandForTest(t, args...); code != 0 {
			t.Errorf("%s via pub file: exit %d\nstdout:\n%s\nstderr:\n%s", name, code, stdout, stderr)
		}
	}

	tamperAuditFile(t, path)
	if code, _, _ := runCommandForTest(t, "verify", "--agent", "kit", "--audit-dir", dir); code != 2 {
		t.Errorf("tampered trail via pub file: exit %d, want 2", code)
	}
}

func TestPubKeyEnvOverridesPubKeyFile(t *testing.T) {
	home := keygenHome(t)
	dir := t.TempDir()
	_, goodPub := writeEd25519Trail(t, dir, "kit")
	otherPub, _, _ := ed25519.GenerateKey(nil)
	badPub := hex.EncodeToString(otherPub)
	if err := os.MkdirAll(policy.AgentKeyDir(home), 0o700); err != nil {
		t.Fatal(err)
	}
	writePub := func(h string) {
		if err := os.WriteFile(policy.AgentPubPath(home, "kit"), []byte(h), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	writePub(badPub)
	t.Setenv(policy.AgentPubKeyEnvName("kit"), goodPub)
	if code, _, stderr := runCommandForTest(t, "verify", "--agent", "kit", "--audit-dir", dir); code != 0 {
		t.Fatalf("env (good) must beat file (bad): exit %d %s", code, stderr)
	}

	writePub(goodPub)
	t.Setenv(policy.AgentPubKeyEnvName("kit"), badPub)
	if code, _, _ := runCommandForTest(t, "verify", "--agent", "kit", "--audit-dir", dir); code == 0 {
		t.Fatal("env (bad) must beat file (good): verify unexpectedly passed")
	}
}

func TestVerifyRefusesGroupWritablePubFile(t *testing.T) {
	home := keygenHome(t)
	dir := t.TempDir()
	_, pubHex := writeEd25519Trail(t, dir, "kit")
	t.Setenv(policy.AgentPubKeyEnvName("kit"), "")
	if err := os.MkdirAll(policy.AgentKeyDir(home), 0o700); err != nil {
		t.Fatal(err)
	}
	p := policy.AgentPubPath(home, "kit")
	if err := os.WriteFile(p, []byte(pubHex), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCommandForTest(t, "verify", "--agent", "kit", "--audit-dir", dir); code != 1 || !strings.Contains(stderr, "writable") {
		t.Fatalf("exit %d stderr %q; want refusal of a world-writable pub file", code, stderr)
	}
}

func TestKeygenAcceptsEqualsForm(t *testing.T) {
	home := keygenHome(t)
	if code, stdout, stderr := runCommandForTest(t, "keygen", "--agent=kit"); code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if _, err := os.Stat(policy.AgentSeedPath(home, "kit")); err != nil {
		t.Errorf("--agent=kit should write kit.ed25519: %v", err)
	}
	if code, _, _ := runCommandForTest(t, "keygen", "--force=1"); code == 0 {
		t.Error("--force=1 must be rejected")
	}
}

func TestObserveBackfillsPubFileForExistingSeed(t *testing.T) {
	home := keygenHome(t)
	if _, _, err := ensureObserveKey(home, "legacy"); err != nil {
		t.Fatal(err)
	}
	pubPath := policy.AgentPubPath(home, "legacy")
	if err := os.Remove(pubPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ensureObserveKey(home, "legacy"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pubPath); err != nil {
		t.Errorf("existing seed should get its .pub backfilled: %v", err)
	}
}

func openKeyDirForTest(t *testing.T, home string) *os.File {
	t.Helper()
	if err := os.MkdirAll(policy.AgentKeyDir(home), 0o700); err != nil {
		t.Fatal(err)
	}
	d, err := os.Open(policy.AgentKeyDir(home))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func newKeyPairHex(t *testing.T) (seedHex, pubHex string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(priv.Seed()), hex.EncodeToString(pub)
}

func requireBlocked(t *testing.T, what string, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
		t.Fatalf("%s finished while the agent key lock was held", what)
	case <-time.After(100 * time.Millisecond):
	}
}

func requireFinishes(t *testing.T, what string, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not finish after the agent key lock was released", what)
	}
}

// assertWaitsForAgentKeyLock holds the agent's key lock, starts op, and checks op
// does not finish until the lock is released.
func assertWaitsForAgentKeyLock(t *testing.T, home, what string, op func() error) {
	t.Helper()
	unlock, err := lockAgentKeys(openKeyDirForTest(t, home), "kit")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := op(); err != nil {
			t.Errorf("%s: %v", what, err)
		}
	}()
	requireBlocked(t, what, done)
	unlock()
	requireFinishes(t, what, done)
}

func TestKeygenForceWaitsForAgentKeyLock(t *testing.T) {
	home := keygenHome(t)
	seed, pub := newKeyPairHex(t)
	assertWaitsForAgentKeyLock(t, home, "keygen --force", func() error {
		_, err := writeKeyFiles(home, "kit", seed, pub, true)
		return err
	})
	if fi, err := os.Stat(filepath.Join(policy.AgentKeyDir(home), "kit.lock")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("lock file: %v, %v; want mode 0600", fi, err)
	}
}

func TestObserveKeyWaitsForAgentKeyLock(t *testing.T) {
	home := keygenHome(t)
	if _, _, err := ensureObserveKey(home, "kit"); err != nil {
		t.Fatal(err)
	}
	assertWaitsForAgentKeyLock(t, home, "observe seed read", func() error {
		_, _, err := ensureObserveKey(home, "kit")
		return err
	})
}

func TestConcurrentKeygenForceKeepsSeedAndPubInStep(t *testing.T) {
	home := keygenHome(t)
	for round := 0; round < 20; round++ {
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			seed, pub := newKeyPairHex(t)
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := writeKeyFiles(home, "kit", seed, pub, true); err != nil {
					t.Errorf("writeKeyFiles: %v", err)
				}
			}()
		}
		wg.Wait()
		seedB, err := os.ReadFile(policy.AgentSeedPath(home, "kit"))
		if err != nil {
			t.Fatal(err)
		}
		pubB, err := os.ReadFile(policy.AgentPubPath(home, "kit"))
		if err != nil {
			t.Fatal(err)
		}
		priv, _, err := loadSeedHex("kit", string(seedB))
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(priv.Public().(ed25519.PublicKey)); got != string(pubB) {
			t.Fatalf("round %d: published pub %s does not belong to the persisted seed (%s)", round, pubB, got)
		}
	}
}

func TestObserveBackfillKeepsMatchingPubAndRepairsMismatch(t *testing.T) {
	home := keygenHome(t)
	_, pub, err := ensureObserveKey(home, "kit")
	if err != nil {
		t.Fatal(err)
	}
	pubPath := policy.AgentPubPath(home, "kit")
	before, err := os.Stat(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ensureObserveKey(home, "kit"); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Error("a .pub that already matches the seed must not be rewritten")
	}

	_, stale := newKeyPairHex(t)
	if err := os.WriteFile(pubPath, []byte(stale), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ensureObserveKey(home, "kit"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(pubPath)
	if err != nil || string(got) != hex.EncodeToString(pub) {
		t.Errorf("mismatched .pub must be repaired from the seed: got %q, %v", got, err)
	}
}

func TestRequirePubHexSaysEmptyForEmptyPubFile(t *testing.T) {
	home := keygenHome(t)
	t.Setenv(policy.AgentPubKeyEnvName("kit"), "")
	openKeyDirForTest(t, home)
	if err := os.WriteFile(policy.AgentPubPath(home, "kit"), []byte(" \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := requirePubHex(policy.AgentPubKeyEnvName("kit"), "kit")
	if err == nil || !strings.Contains(err.Error(), "empty") || strings.Contains(err.Error(), "does not exist") || !strings.Contains(err.Error(), policy.AgentPubPath(home, "kit")) {
		t.Fatalf("got %v, want an error naming the path and saying the file is empty", err)
	}
}

func TestVerifyReportsPublicKeySource(t *testing.T) {
	home := keygenHome(t)
	dir := t.TempDir()
	_, pubHex := writeEd25519Trail(t, dir, "kit")
	pubPath := policy.AgentPubPath(home, "kit")
	openKeyDirForTest(t, home)
	if err := os.WriteFile(pubPath, []byte(pubHex), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv(policy.AgentPubKeyEnvName("kit"), "")
	for name, args := range map[string][]string{
		"verify":     {"verify", "--agent", "kit", "--audit-dir", dir},
		"verify all": {"verify", "--all", "--audit-dir", dir},
	} {
		if code, stdout, stderr := runCommandForTest(t, args...); code != 0 || !strings.Contains(stdout, "public key: "+pubPath) {
			t.Errorf("%s: exit %d, want the .pub path reported\nstdout:\n%s\nstderr:\n%s", name, code, stdout, stderr)
		}
	}
	code, stdout, _ := runCommandForTest(t, "verify", "--agent", "kit", "--audit-dir", dir, "--json")
	var res verifyResult
	if err := json.Unmarshal([]byte(stdout), &res); code != 0 || err != nil || res.PubKeySource != pubPath {
		t.Errorf("--json must carry public_key_source=%s; exit %d, err %v, stdout %s", pubPath, code, err, stdout)
	}

	t.Setenv(policy.AgentPubKeyEnvName("kit"), pubHex)
	if code, stdout, _ := runCommandForTest(t, "verify", "--agent", "kit", "--audit-dir", dir); code != 0 || !strings.Contains(stdout, "public key: "+policy.AgentPubKeyEnvName("kit")) {
		t.Errorf("env source: exit %d stdout %s", code, stdout)
	}
}

func TestObserveBackfillRepublishesMatchingPubThatVerifyWouldReject(t *testing.T) {
	home := keygenHome(t)
	_, pub, err := ensureObserveKey(home, "kit")
	if err != nil {
		t.Fatal(err)
	}
	pubPath := policy.AgentPubPath(home, "kit")
	if err := os.Chmod(pubPath, 0o666); err != nil {
		t.Fatal(err)
	}
	t.Setenv(policy.AgentPubKeyEnvName("kit"), "")
	if _, _, err := policy.ResolveAgentPub("kit"); err == nil {
		t.Fatal("precondition: a 0666 pub file must be rejected by the verifier")
	}
	if _, _, err := ensureObserveKey(home, "kit"); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(pubPath)
	if err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("got mode %v, %v; want republished at 0644", st.Mode().Perm(), err)
	}
	if got, _, err := policy.ResolveAgentPub("kit"); err != nil || got != hex.EncodeToString(pub) {
		t.Fatalf("verify side rejects the republished pub: (%q, %v)", got, err)
	}
}
