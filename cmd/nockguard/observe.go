package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/policy"
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

	// (2) Persisted per-agent key.
	keyDir := filepath.Join(home, ".nockguard", "keys")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("creating key dir %s: %w", keyDir, err)
	}
	keyPath := filepath.Join(keyDir, agent+".ed25519")
	pubPath := keyPath + ".pub"

	// Reuse an existing key if present.
	if seedHex, rerr := os.ReadFile(keyPath); rerr == nil {
		return loadSeedHex(keyPath, string(seedHex))
	} else if !os.IsNotExist(rerr) {
		return nil, nil, fmt.Errorf("reading persisted key %s: %w", keyPath, rerr)
	}

	// Generate and persist once. Write the complete seed to a same-directory temp
	// file, then atomically link it into place without replacing an existing key.
	// A racing loser can therefore only observe the winner's complete seed.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating observe key: %w", err)
	}
	seedHex := hex.EncodeToString(priv.Seed())
	f, err := os.CreateTemp(keyDir, ".observe-key-*")
	if err != nil {
		return nil, nil, fmt.Errorf("creating temporary key in %s: %w", keyDir, err)
	}
	tempPath := f.Name()
	defer os.Remove(tempPath)
	if _, werr := f.WriteString(seedHex); werr != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("writing temporary key %s: %w", tempPath, werr)
	}
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("syncing temporary key %s: %w", tempPath, serr)
	}
	if cerr := f.Close(); cerr != nil {
		return nil, nil, fmt.Errorf("closing temporary key %s: %w", tempPath, cerr)
	}
	if lerr := os.Link(tempPath, keyPath); lerr != nil {
		if os.IsExist(lerr) {
			winner, rerr := os.ReadFile(keyPath)
			if rerr != nil {
				return nil, nil, fmt.Errorf("reading raced key %s: %w", keyPath, rerr)
			}
			return loadSeedHex(keyPath, string(winner))
		}
		return nil, nil, fmt.Errorf("publishing key file %s: %w", keyPath, lerr)
	}
	// os.Link added a new entry to keyDir; the entry itself is only durable once
	// the directory is fsync'd. Without this, a crash after the trail is written
	// can discard the key file while the trail it signed survives — and the next
	// run's freshly generated key makes audit.New reject the existing chain,
	// permanently bricking observe. Fail loudly rather than persist a key whose
	// directory entry is not durable (matches the temp-file Sync above).
	if dirFile, derr := os.Open(keyDir); derr != nil {
		return nil, nil, fmt.Errorf("opening key dir %s to sync: %w", keyDir, derr)
	} else if serr := dirFile.Sync(); serr != nil {
		_ = dirFile.Close()
		return nil, nil, fmt.Errorf("syncing key dir %s: %w", keyDir, serr)
	} else if cerr := dirFile.Close(); cerr != nil {
		return nil, nil, fmt.Errorf("closing key dir %s: %w", keyDir, cerr)
	}
	// Best-effort: the public half alongside the seed, for convenience. Its
	// absence is not fatal — the banner already prints the hex public key.
	_ = os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)), 0o644)
	return priv, pub, nil
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
