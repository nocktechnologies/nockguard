package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/policy"
	"github.com/nocktechnologies/nockguard/internal/sessionverify"
)

// Verification status values reported in verifyReport.Status. They let the
// browser tell an UNAVAILABLE trail (could not be read — e.g. a line past the
// scanner cap) apart from a real TAMPER, so a benign read glitch never fires the
// loud tamper banner.
const (
	statusVerified     = "verified"     // chain walked clean end to end
	statusTampered     = "tampered"     // a real chain/signature break (banner fires)
	statusUnavailable  = "unavailable"  // read/scan/IO error — chain_intact stays null
	statusUnconfigured = "unconfigured" // no signing key configured — chain_intact null
	statusNoRows       = "no_rows"      // no audit evidence to verify
	statusUnanchored   = "unanchored"   // signatures pass, but the checkpoint misses the trail tail
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
	mode      verifyMode
	key       []byte            // HMAC key (modeHMAC)
	pub       ed25519.PublicKey // Ed25519 public key (modeEd25519)
	pubSource string
}

// enabled reports whether a verification key is configured. Nil-safe so a broker
// built without a verifier (e.g. in tests) degrades to "unknown" rather than
// panicking.
func (v *verifier) enabled() bool { return v != nil && v.mode != modeNone }

// newVerifier resolves trusted keys server-side. Agent Ed25519 keys use the
// same resolver as `nockguard verify --agent`: the canonical env var wins, then
// the protected per-agent .pub file. Explicit custom env-var flags remain
// environment-only. Ed25519 takes precedence over HMAC when both are set.
func newVerifier(pubEnv, keyEnv, agent string) (*verifier, error) {
	v := &verifier{mode: modeNone}
	if pubEnv != "" {
		var pubHex, source string
		if agent != "" && pubEnv == policy.AgentPubKeyEnvName(agent) {
			var err error
			pubHex, source, err = policy.ResolveAgentPub(agent)
			if err != nil {
				return nil, fmt.Errorf("resolve public key for agent %s: %w", agent, err)
			}
		} else {
			pubHex = strings.TrimSpace(os.Getenv(pubEnv))
			source = pubEnv
		}
		if pubHex != "" {
			pub, err := audit.PublicKeyFromHex(pubHex)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", source, err)
			}
			v.mode = modeEd25519
			v.pub = pub
			v.pubSource = source
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
	AuditFailing    bool    `json:"audit_failing"`
	ChainIntact     *bool   `json:"chain_intact"`
	Verdict         string  `json:"verdict"`
	PublicKeySource string  `json:"public_key_source,omitempty"`
	EntriesVerified int     `json:"entries_verified"`
	BreakAt         *int    `json:"break_at"`
	LastVerifiedAt  string  `json:"last_verified_at"`
	Detail          *string `json:"detail"`
	// Status names the verification outcome so the browser can distinguish an
	// UNAVAILABLE trail (a read/scan error — chain_intact null) from a real
	// TAMPER (chain_intact false). Only "tampered" fires the banner; other
	// non-protected states are shown as status notes. See N9870.
	Status string `json:"status"`
}

func strptr(s string) *string { return &s }
func boolptr(b bool) *bool    { return &b }
func intptr(i int) *int       { return &i }

// verify runs the EXISTING internal/audit chain verification over the trail at
// path and folds the result into a verifyReport. It NEVER reimplements the crypto
// — it calls the snapshot variants of audit.Verify (HMAC) / audit.VerifyEd25519
// (Ed25519), using the same verification as `nockguard audit verify`.
func (v *verifier) verify(path string) verifyReport {
	now := time.Now().Format(time.RFC3339)
	if !v.enabled() {
		return v.verifySnapshot(nil, nil, now)
	}
	trail, hwm, err := sessionverify.ReadGuard(path, maxExportTrailBytes)
	if err != nil {
		rep := classifyVerifyResult(0, err, now)
		rep.PublicKeySource = v.pubSource
		return rep
	}
	return v.verifySnapshot(trail, hwm, now)
}

func (v *verifier) verifySnapshot(trail, hwm []byte, now string) verifyReport {
	rep, _ := v.verifySnapshotWithCheck(trail, hwm, now)
	return rep
}

func (v *verifier) verifySnapshotWithCheck(trail, hwm []byte, now string) (verifyReport, *sessionverify.GuardCheck) {
	if !v.enabled() {
		return verifyReport{
			LastVerifiedAt: now,
			Status:         statusUnconfigured,
			Verdict:        "UNCONFIGURED",
			Detail:         strptr("audit signing not configured — chain not verified (set --verify-ed25519-pub-env or --verify-key-env)"),
		}, nil
	}
	var check *sessionverify.GuardCheck
	switch v.mode {
	case modeEd25519:
		check = sessionverify.CheckGuard(trail, hwm, v.pub)
	default:
		check = sessionverify.CheckGuardHMAC(trail, hwm, v.key)
	}
	rep := guardReport(check.Trail(), now)
	rep.PublicKeySource = v.pubSource
	if v.mode != modeEd25519 {
		check = nil
	}
	return rep, check
}

// verifyBytes verifies one immutable trail/checkpoint snapshot, so callers can
// decode exactly the bytes whose signatures were checked.
func (v *verifier) verifyBytes(trail, hwm []byte) verifyReport {
	return v.verifySnapshot(trail, hwm, time.Now().Format(time.RFC3339))
}

func guardReport(c sessionverify.ChainResult, now string) verifyReport {
	rep := verifyReport{LastVerifiedAt: now, EntriesVerified: c.EntriesVerified}
	switch c.Verdict {
	case sessionverify.VerdictProtected:
		rep.ChainIntact = boolptr(true)
		rep.Status = statusVerified
		rep.Verdict = sessionverify.VerdictProtected
	case sessionverify.VerdictNoRows:
		rep.ChainIntact = boolptr(true)
		rep.Status = statusNoRows
		rep.Verdict = sessionverify.VerdictNoRows
		rep.Detail = strptr(c.Reason)
	case sessionverify.VerdictUnanchored:
		rep.ChainIntact = boolptr(true)
		rep.Status = statusUnanchored
		rep.Verdict = sessionverify.VerdictUnanchored
		rep.Detail = strptr(c.Reason)
	case sessionverify.VerdictTampered:
		rep.ChainIntact = boolptr(false)
		rep.Status = statusTampered
		rep.Verdict = sessionverify.VerdictTampered
		rep.Detail = strptr(c.Reason)
		if c.FirstBadRow > 0 {
			rep.EntriesVerified = int(c.FirstBadRow) - 1
			badRow := int(c.FirstBadRow)
			rep.BreakAt = &badRow
		}
	default:
		rep.Status = statusUnavailable
		rep.Verdict = "UNAVAILABLE"
		rep.Detail = strptr(c.Reason)
	}
	return rep
}

// classifyVerifyResult folds internal/audit's (entries, err) contract into a
// verifyReport, distinguishing a REAL tamper from a benign read/scan failure —
// the crux of N9870. Only errors.Is(err, audit.ErrTamper) sets chain_intact=false
// (which fires the wall's tamper banner). A scan/IO error (audit.ErrScan, an
// absent/unreadable trail, or an unclassified internal error) leaves chain_intact
// NULL and reports status "unavailable", so a long-line read glitch or a missing
// file never cries wolf. It is a pure function of (n, err, now) so it is unit
// tested directly with synthetic errors, no fixtures.
func classifyVerifyResult(n int, err error, now string) verifyReport {
	rep := verifyReport{LastVerifiedAt: now}
	if err == nil {
		rep.ChainIntact = boolptr(true)
		rep.EntriesVerified = n
		rep.Status = statusVerified
		return rep
	}
	if errors.Is(err, audit.ErrTamper) {
		// Genuine chain break — the banner must fire. Attribution comes from the
		// tamper's Line, NOT the returned count n: an in-loop signature failure sets
		// Line = the 1-based entry that FAILED (entries before it verified clean),
		// while a high-water-mark / checkpoint failure sets Line = 0 because every
		// entry the walk reached verified clean and the break is at the boundary,
		// not a scanned line.
		rep.ChainIntact = boolptr(false)
		rep.Detail = strptr(err.Error())
		rep.Status = statusTampered
		rep.Verdict = "TAMPERED"
		line := 0
		var te *audit.TamperError
		if errors.As(err, &te) {
			line = te.Line
		}
		if line >= 1 {
			// Line-scoped break: report where it broke and count the clean entries
			// before it.
			verified := line - 1
			if verified < 0 {
				verified = 0
			}
			rep.EntriesVerified = verified
			rep.BreakAt = intptr(line)
		} else {
			// Boundary tamper (Line 0): all n scanned entries verified clean; there
			// is no single break line, so retain n and omit break_at. Every per-event
			// badge falls through to "unknown" (lineState) because the chain as a
			// whole can no longer be trusted past the boundary.
			rep.EntriesVerified = n
		}
		return rep
	}
	// Read/scan or IO error: verification is UNAVAILABLE, not failed. chain_intact
	// stays null (never false) so the tamper banner does NOT fire; entries_verified
	// keeps whatever count was read before the failure as information.
	rep.EntriesVerified = n
	rep.Status = statusUnavailable
	rep.Verdict = "UNAVAILABLE"
	rep.Detail = strptr(err.Error())
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
