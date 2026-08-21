package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
)

// verifyMode names the cryptographic mode the wall uses to verify the audit chain.
type verifyMode int

const (
	modeNone    verifyMode = iota // no key configured — verification disabled
	modeHMAC                      // symmetric HMAC-SHA256 (tamper-evident)
	modeEd25519                   // asymmetric Ed25519 public key (non-repudiable)
)

// verifier holds the TRUSTED key the wall verifies its audit trail with. The key
// is sourced SERVER-SIDE only — from an environment variable named by a flag,
// exactly the way `nockguard audit verify` sources it (cmd/nockguard/main.go).
// A browser NEVER supplies a key: there is deliberately no ?pub=/?key= request
// parameter, so a client cannot swap in a key that would make a tampered trail
// verify clean (decision b).
type verifier struct {
	mode verifyMode
	key  []byte            // HMAC key (modeHMAC)
	pub  ed25519.PublicKey // Ed25519 public key (modeEd25519)
}

// enabled reports whether a verification key is configured. Nil-safe so a broker
// built without a verifier (e.g. in tests) degrades to "unknown" rather than
// panicking.
func (v *verifier) enabled() bool { return v != nil && v.mode != modeNone }

// newVerifier resolves the wall's TRUSTED verification key from the environment,
// by env-var NAME supplied server-side — the same sourcing the `nockguard audit
// verify` CLI uses (cmd/nockguard/main.go:704-722). Ed25519 (public key) takes
// precedence over HMAC when both env vars are populated, mirroring the auditor's
// own precedence (internal/policy/policy.go auditorAt). When neither var is set
// the verifier is disabled (mode none): the wall still tails, per-event badges
// read "unknown", and /verify reports chain_intact:null so no false tamper banner
// fires.
func newVerifier(pubEnv, keyEnv string) (*verifier, error) {
	v := &verifier{mode: modeNone}
	if pubEnv != "" {
		if pubHex := strings.TrimSpace(os.Getenv(pubEnv)); pubHex != "" {
			pub, err := audit.PublicKeyFromHex(pubHex)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", pubEnv, err)
			}
			v.mode = modeEd25519
			v.pub = pub
			return v, nil
		}
	}
	if keyEnv != "" {
		if key := os.Getenv(keyEnv); key != "" {
			v.mode = modeHMAC
			v.key = []byte(key)
			return v, nil
		}
	}
	return v, nil
}

// verifyReport is the JSON shape /verify returns AND the snapshot the wall caches
// to enrich per-event badges. chain_intact is a *bool so an unconfigured wall
// reports null (unknown) — a null never trips the tamper banner, only an explicit
// false does. break_at is the 1-based line index of the FIRST broken entry;
// entries_verified counts the entries that passed BEFORE the break, so on a
// tamper break_at == entries_verified+1.
type verifyReport struct {
	ChainIntact     *bool   `json:"chain_intact"`
	EntriesVerified int     `json:"entries_verified"`
	BreakAt         *int    `json:"break_at"`
	LastVerifiedAt  string  `json:"last_verified_at"`
	Detail          *string `json:"detail"`
}

func strptr(s string) *string { return &s }
func boolptr(b bool) *bool    { return &b }
func intptr(i int) *int       { return &i }

// verify runs the EXISTING internal/audit chain verification over the trail at
// path and folds the result into a verifyReport. It NEVER reimplements the crypto
// — it calls audit.Verify (HMAC) / audit.VerifyEd25519 (Ed25519), the same
// functions `nockguard audit verify` runs.
func (v *verifier) verify(path string) verifyReport {
	rep := verifyReport{LastVerifiedAt: time.Now().Format(time.RFC3339)}
	if !v.enabled() {
		rep.Detail = strptr("audit signing not configured — chain not verified (set --verify-ed25519-pub-env or --verify-key-env)")
		return rep
	}
	var (
		n   int
		err error
	)
	switch v.mode {
	case modeEd25519:
		n, err = audit.VerifyEd25519(path, v.pub)
	default:
		n, err = audit.Verify(path, v.key)
	}
	if err != nil {
		if n <= 0 {
			// Could not read the trail (absent/unreadable/empty-unsigned) rather
			// than a chain break: report unknown, not a false tamper. audit.Verify
			// only returns a positive line number once it has counted entries.
			rep.Detail = strptr(err.Error())
			return rep
		}
		// audit.Verify returns n = the 1-based line that FAILED; the entries before
		// it verified clean.
		verified := n - 1
		if verified < 0 {
			verified = 0
		}
		rep.ChainIntact = boolptr(false)
		rep.EntriesVerified = verified
		rep.BreakAt = intptr(n)
		rep.Detail = strptr(err.Error())
		return rep
	}
	rep.ChainIntact = boolptr(true)
	rep.EntriesVerified = n
	return rep
}

// lineState maps a 1-based audit line index to a per-event verification badge
// state, given a cached full-verify snapshot. Lines before the break verified
// clean ("ok"); the broken line itself is "broken"; everything at/after it can no
// longer be trusted ("unknown"). With no snapshot (chain_intact null) or an
// unbroken chain the answer is uniform.
func lineState(rep verifyReport, line int) string {
	if rep.ChainIntact == nil {
		return "unknown"
	}
	if *rep.ChainIntact {
		return "ok"
	}
	if rep.BreakAt == nil {
		return "unknown"
	}
	switch {
	case line < *rep.BreakAt:
		return "ok"
	case line == *rep.BreakAt:
		return "broken"
	default:
		return "unknown"
	}
}

// handleVerify runs a FULL chain verification over the tailed trail and returns
// the verifyReport as JSON. This is the on-demand + page-load full walk (decision
// a); it also refreshes the cached snapshot the live per-event badges read. The
// trusted key is the server-configured one — there is NO client-supplied key
// parameter, and ?agent= is not honoured because this wall tails a single trail.
func (b *broker) handleVerify(w http.ResponseWriter, r *http.Request) {
	rep := b.refreshSnapshot()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rep)
}
