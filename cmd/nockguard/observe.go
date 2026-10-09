package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/policy"
	"golang.org/x/sys/unix"
)

// defaultObserveAgent is the agent identity used by zero-config observe mode when
// the user runs `proxy --upstream <x>` without naming an --agent. It intentionally
// mirrors the "default" policy fallback keyword so the observe engine's single
// allow-all agent governs every call.
const defaultObserveAgent = "default"

// observePolicyYAML is the in-memory zero-config OBSERVE policy: one "default"
// agent in allow mode — allow every tool, deny nothing. It is loaded through the
// real policy loader (policy.LoadBytes), so the observe engine is parsed and
// validated exactly like an on-disk policy. Observe mode is an EXPLICIT, logged
// posture (see printObserveBanner), never a silent bypass of a configured
// enforce: it is reached ONLY when no policy file exists (see runCLI's proxy
// branch), so a present/named policy is always honored unchanged.
const observePolicyYAML = `agents:
  default:
    mode: allow
`

// observeSetup builds the zero-config OBSERVE engine and a signed, per-agent
// audit trail for the no-policy-file case. It returns the allow-all engine, an
// Ed25519-signing Auditor writing to the standard per-agent trail path, that
// path, and the hex public key a verifier needs. The private key is persisted
// (or an explicitly-set per-agent key env is honored) so the trail stays
// verifiable across runs — see ensureObserveKey.
func observeSetup(agent string) (engine *policy.Engine, auditor *audit.Auditor, auditPath, pubHex string, err error) {
	if !policy.ValidAgentName(agent) {
		return nil, nil, "", "", fmt.Errorf("invalid agent name %q", agent)
	}

	engine, err = policy.LoadBytes([]byte(observePolicyYAML))
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("building observe policy: %w", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("cannot determine home directory: %w", err)
	}

	priv, pub, err := ensureObserveKey(home, agent)
	if err != nil {
		return nil, nil, "", "", err
	}

	// Write to the SAME per-agent trail path `nockguard verify --agent <name>`
	// reads, so the printed verify command works without further wiring.
	auditPath = policy.AgentAuditPath(filepath.Join(home, policy.DefaultAuditPath), agent)
	auditor, err = audit.New(auditPath, audit.WithEd25519Key(priv))
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("opening signed audit trail %s: %w", auditPath, err)
	}
	return engine, auditor, auditPath, hex.EncodeToString(pub), nil
}

// ensureObserveKey returns the Ed25519 keypair that signs the zero-config observe
// trail. It resolves the key in this order:
//
//  1. An explicitly-set per-agent key env (NOCKGUARD_AGENT_<NAME>_ED25519_KEY,
//     e.g. from `nockguard keygen --agent <name>`). Honoring it keeps a user who
//     followed the documented signing flow on ONE key, so the signed trail's
//     verify-on-open never trips a false tamper from a second, competing key.
//  2. A persisted per-agent key under ~/.nockguard/keys/<agent>.ed25519 (mode
//     0600, dir 0700), generated once on first run and reused thereafter.
//
// Persistence is REQUIRED, not a convenience: audit.New re-verifies the existing
// chain with this key's public half on open, so a fresh key each run would refuse
// to append to an existing trail. Reusing one key keeps the trail verifiable.
func ensureObserveKey(home, agent string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	// (1) Explicit per-agent key env takes precedence.
	if raw := os.Getenv(policy.AgentKeyEnvName(agent)); raw != "" {
		priv, err := audit.PrivateKeyFromHex(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("per-agent key env %s: %w", policy.AgentKeyEnvName(agent), err)
		}
		pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			return nil, nil, fmt.Errorf("per-agent key env %s has no usable public key", policy.AgentKeyEnvName(agent))
		}
		return priv, pub, nil
	}

	// (2) Persisted per-agent key. Keep directory handles open from validation
	// through publication: path-based checks followed by os.MkdirAll, CreateTemp,
	// or Link can be redirected by a swapped symlink. openat with O_NOFOLLOW
	// binds every operation to the directory descriptor we validated instead.
	homeDir, err := os.Open(home)
	if err != nil {
		return nil, nil, fmt.Errorf("opening home dir %s: %w", home, err)
	}
	defer homeDir.Close()
	if info, err := homeDir.Stat(); err != nil {
		return nil, nil, fmt.Errorf("stating home dir %s: %w", home, err)
	} else if !info.IsDir() {
		return nil, nil, fmt.Errorf("home path %s is not a directory", home)
	}

	nockguardDir, err := openOrCreateObserveDir(int(homeDir.Fd()), ".nockguard", 0o700, unix.Fsync)
	if err != nil {
		return nil, nil, fmt.Errorf("opening nockguard state dir: %w", err)
	}
	defer nockguardDir.Close()
	keyDir, err := openOrCreateObserveDir(int(nockguardDir.Fd()), "keys", 0o700, unix.Fsync)
	if err != nil {
		return nil, nil, fmt.Errorf("opening observe key dir: %w", err)
	}
	defer keyDir.Close()

	// Hold the per-agent lock from the first read through the .pub publication so
	// a concurrent `keygen --force` cannot rotate the seed between our read and
	// our backfill.
	unlock, err := lockAgentKeys(keyDir, agent)
	if err != nil {
		return nil, nil, err
	}
	defer unlock()

	keyName := agent + ".ed25519"
	keyPath := policy.AgentSeedPath(home, agent)
	// Reuse an existing key if present. The directory-relative Lstat and
	// no-follow open reject symlinks both before and during this read.
	if seedHex, exists, rerr := readObserveKey(int(keyDir.Fd()), keyName); rerr != nil {
		return nil, nil, fmt.Errorf("reading persisted key %s: %w", keyPath, rerr)
	} else if exists {
		priv, pub, lerr := loadSeedHex(keyPath, string(seedHex))
		if lerr == nil {
			// Keys created by an earlier release have no <agent>.pub; backfill it,
			// and repair one that no longer matches the seed.
			ensurePubFile(keyDir, agent+".pub", hex.EncodeToString(pub))
		}
		return priv, pub, lerr
	}

	// Generate and persist once. Write the complete seed to a same-directory temp
	// file, then atomically link it into place without replacing an existing key.
	// A racing loser can therefore only observe the winner's complete seed.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating observe key: %w", err)
	}
	seedHex := hex.EncodeToString(priv.Seed())
	if perr := publishKeyFile(keyDir, keyName, []byte(seedHex), 0o600, false); perr != nil {
		if !errors.Is(perr, unix.EEXIST) {
			return nil, nil, fmt.Errorf("publishing key file %s: %w", keyPath, perr)
		}
		winner, exists, rerr := readObserveKey(int(keyDir.Fd()), keyName)
		if rerr != nil {
			return nil, nil, fmt.Errorf("reading raced key %s: %w", keyPath, rerr)
		}
		if !exists {
			return nil, nil, fmt.Errorf("raced key %s disappeared before it could be read", keyPath)
		}
		return loadSeedHex(keyPath, string(winner))
	}
	// Best-effort: the public half alongside the seed, so `verify --agent` finds
	// it by name. Its absence is not fatal — the banner already prints the hex key.
	_ = publishKeyFile(keyDir, agent+".pub", []byte(hex.EncodeToString(pub)), 0o644, true)
	return priv, pub, nil
}

// ensurePubFile publishes name unless it already holds pubHex as a regular file
// owned by us that is not group/other writable (what verify accepts). The caller
// holds the agent's key lock and pubHex derives from the seed read under it, so
// this can never replace a rotated pub with one from an older seed. Best-effort,
// like the original backfill.
func ensurePubFile(keyDir *os.File, name, pubHex string) {
	if fd, err := unix.Openat(int(keyDir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0); err == nil {
		f := os.NewFile(uintptr(fd), name)
		var st unix.Stat_t
		// Same bar as policy.ResolveAgentPub: a file verify would reject is republished.
		if unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Uid == uint32(os.Geteuid()) && st.Mode&0o022 == 0 {
			if b, err := io.ReadAll(io.LimitReader(f, 4096)); err == nil && strings.TrimSpace(string(b)) == pubHex {
				_ = f.Close()
				return
			}
		}
		_ = f.Close()
	}
	_ = publishKeyFile(keyDir, name, []byte(pubHex), 0o644, true)
}

// openOrCreateObserveDir creates one state-path component when absent, then
// validates it through a no-follow descriptor. It synchronizes parentFD after
// both Mkdirat success and EEXIST: the latter can lose a race with the creator,
// whose directory entry may not yet be durable.
func openOrCreateObserveDir(parentFD int, name string, perm uint32, syncParent func(int) error) (*os.File, error) {
	err := unix.Mkdirat(parentFD, name, perm)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	created := err == nil

	var lstat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &lstat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	if lstat.Mode&unix.S_IFMT == unix.S_IFLNK {
		return nil, fmt.Errorf("%s is a symlink", name)
	}

	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), name)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = dir.Close()
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = dir.Close()
		return nil, fmt.Errorf("%s is not a directory", name)
	}
	if stat.Uid != uint32(os.Geteuid()) {
		_ = dir.Close()
		return nil, fmt.Errorf("%s owner uid = %d, want %d", name, stat.Uid, os.Geteuid())
	}
	mode := uint32(stat.Mode) & 0o777
	if !created && name == "keys" && mode&0o022 != 0 {
		_ = dir.Close()
		return nil, fmt.Errorf("%s permissions = %o: group/other writable; inspect and recreate the directory", name, mode)
	}
	if created || (name == "keys" && mode&0o055 != 0) {
		if err := unix.Fchmod(fd, perm); err != nil {
			_ = dir.Close()
			return nil, fmt.Errorf("setting %s permissions: %w", name, err)
		}
		if !created {
			log.Printf("[nockguard] tightening observe key dir permissions from %o to %o", mode, perm)
		}
		if err := unix.Fsync(fd); err != nil {
			_ = dir.Close()
			return nil, fmt.Errorf("syncing %s permissions: %w", name, err)
		}
		if err := unix.Fstat(fd, &stat); err != nil {
			_ = dir.Close()
			return nil, err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			_ = dir.Close()
			return nil, fmt.Errorf("%s is not a directory", name)
		}
		if stat.Uid != uint32(os.Geteuid()) {
			_ = dir.Close()
			return nil, fmt.Errorf("%s owner uid = %d, want %d", name, stat.Uid, os.Geteuid())
		}
		mode = uint32(stat.Mode) & 0o777
		if mode != perm {
			_ = dir.Close()
			return nil, fmt.Errorf("%s permissions = %o, want %o", name, mode, perm)
		}
	}
	if name == "keys" && mode&0o077 != 0 {
		_ = dir.Close()
		return nil, fmt.Errorf("%s permissions = %o, want no group or other access", name, mode)
	}
	if name != "keys" && mode&0o022 != 0 {
		_ = dir.Close()
		return nil, fmt.Errorf("%s permissions = %o, want no group or other write access", name, mode)
	}
	if err := syncParent(parentFD); err != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("syncing directory parent: %w", err)
	}
	return dir, nil
}

// readObserveKey reads a persisted seed through a no-follow descriptor. Its
// Lstat is relative to the already-validated keys directory; the Fstat after
// opening detects a regular-file replacement during that small interval.
func readObserveKey(dirFD int, name string) ([]byte, bool, error) {
	var before unix.Stat_t
	if err := unix.Fstatat(dirFD, name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if before.Mode&unix.S_IFMT == unix.S_IFLNK {
		return nil, true, fmt.Errorf("%s is a symlink", name)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, true, fmt.Errorf("%s is not a regular file", name)
	}

	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, true, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return nil, true, err
	}
	if before.Dev != after.Dev || before.Ino != after.Ino {
		return nil, true, fmt.Errorf("%s was replaced while being opened", name)
	}
	if after.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, true, fmt.Errorf("%s is not a regular file", name)
	}
	if after.Uid != uint32(os.Geteuid()) {
		return nil, true, fmt.Errorf("%s owner uid = %d, want %d", name, after.Uid, os.Geteuid())
	}
	if mode := uint32(after.Mode) & 0o777; mode&0o077 != 0 {
		return nil, true, fmt.Errorf("%s permissions = %o: group/other readable or writable; inspect and recreate the key file", name, mode)
	}
	seedHex, err := io.ReadAll(f)
	return seedHex, true, err
}

// loadSeedHex parses a persisted hex seed into a keypair.
func loadSeedHex(keyPath, seedHex string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	priv, err := audit.PrivateKeyFromHex(strings.TrimSpace(seedHex))
	if err != nil {
		return nil, nil, fmt.Errorf("parsing persisted key %s: %w", keyPath, err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("persisted key %s has no usable public key", keyPath)
	}
	return priv, pub, nil
}

// printObserveBanner announces zero-config observe mode: what it is doing, where
// the signed trail is, how to verify it, and how to promote to an enforcing
// policy. It writes to w (stderr in production) — NEVER stdout, which carries the
// MCP JSON-RPC wire.
func printObserveBanner(w io.Writer, agent, auditPath, pubHex, policyPath string) {
	fmt.Fprintf(w, "[nockguard] OBSERVE MODE (zero-config): no policy file at %s.\n", policyPath)
	fmt.Fprintf(w, "[nockguard]   Allowing all tools and denying nothing — recording a signed, tamper-evident audit trail. This is observe, not enforce: nothing is blocked.\n")
	fmt.Fprintf(w, "[nockguard]   agent:       %s\n", agent)
	fmt.Fprintf(w, "[nockguard]   audit trail: %s  (Ed25519-signed)\n", auditPath)
	fmt.Fprintf(w, "[nockguard]   verify it:   %s=%s nockguard verify --agent %s\n", policy.AgentPubKeyEnvName(agent), pubHex, agent)
	fmt.Fprintf(w, "[nockguard]   promote to enforce: run `nockguard policy propose --agent %s` (observe-derived allowlist) or `nockguard init` (default-deny starter), then re-run proxy with --policy <file>.\n", agent)
}
