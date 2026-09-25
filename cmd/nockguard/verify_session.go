package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/nocktechnologies/nocklock/pkg/receipt"

	"github.com/nocktechnologies/nockguard/internal/audit"
)

// `nockguard verify --session <id>` gives ONE verdict for one nocklock session
// across both chains that recorded it: the NockLock SQLite log (verified by
// nocklock's public pkg/receipt, the same chain code nocklock itself runs) and
// a NockGuard Ed25519 JSONL trail (verified by audit.VerifyEd25519, the same
// verifier behind `nockguard verify`). Inputs are explicit paths only; there
// is no discovery, and any missing or unreadable input is a failure.
//
// Unified verdict: PROTECTED only when BOTH chains verify, BOTH hold at least
// one row for the session, and BOTH tails are verified (Lock: the signed
// chain_head anchors the walked chain; Guard: the signed .hwm sidecar exists
// and matched). Otherwise the worst per-chain verdict by
// TAMPERED > UNVERIFIABLE > UNSIGNED > NO_ROWS > UNANCHORED.
// Exit codes follow `verify`: 0 = PROTECTED, 2 = TAMPERED, 1 = anything else.

const (
	sessionVerdictProtected    = "PROTECTED"
	sessionVerdictTampered     = "TAMPERED"
	sessionVerdictUnverifiable = "UNVERIFIABLE"
	sessionVerdictUnsigned     = "UNSIGNED"
	sessionVerdictNoRows       = "NO_ROWS"
	sessionVerdictUnanchored   = "UNANCHORED"
	chainVerdictIntact         = "INTACT"
)

// sessionRollbackNote is printed on every run, success or not: the residual
// this command cannot see.
const sessionRollbackNote = "Not checked here: a rollback of a whole chain together with its signed head " +
	"(NockLock chain_head, NockGuard .hwm) to an earlier genuine state passes every local check. " +
	"Only `nocklock verify --against-remote-anchor` detects that, and only for the NockLock chain; " +
	"this command consults no anchor."

// sessionFailRank orders failing verdicts, worst first.
var sessionFailRank = map[string]int{
	sessionVerdictTampered:     5,
	sessionVerdictUnverifiable: 4,
	sessionVerdictUnsigned:     3,
	sessionVerdictNoRows:       2,
	sessionVerdictUnanchored:   1,
}

type sessionChainResult struct {
	Path            string `json:"path"`
	Verdict         string `json:"verdict"`
	KeyID           string `json:"key_id"`
	Rows            int    `json:"rows"`                       // rows/lines belonging to the session
	EntriesVerified int    `json:"entries_verified,omitempty"` // Guard: lines verified in the whole trail
	TailVerified    bool   `json:"tail_verified"`
	TailReason      string `json:"tail_reason,omitempty"`
	FirstBadRow     int64  `json:"first_bad_row,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

type sessionVerifyResult struct {
	Verdict      string             `json:"verdict"`
	SessionID    string             `json:"session_id"`
	Lock         sessionChainResult `json:"lock"`
	Guard        sessionChainResult `json:"guard"`
	RollbackNote string             `json:"rollback_note"`
}

const sessionUsage = "usage: nockguard verify --session <id> --lock-db <path> --guard-trail <path> (--pub-env <ENV> | --lock-pub-env <ENV> --guard-pub-env <ENV>) [--json]"

// hasSessionFlag reports whether a verify invocation is the --session form.
func hasSessionFlag(args []string) bool {
	for _, a := range args {
		if a == "--session" {
			return true
		}
	}
	return false
}

func keyFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

func loadPubFromEnv(envName string) (ed25519.PublicKey, error) {
	v := os.Getenv(envName)
	if v == "" {
		return nil, fmt.Errorf("%s is not set in the environment", envName)
	}
	pub, err := audit.PublicKeyFromHex(v)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envName, err)
	}
	return pub, nil
}

// runVerifySession parses the flags after "verify" and runs the check.
func runVerifySession(args []string) int {
	var session, lockDB, guardTrail, pubEnv, lockPubEnv, guardPubEnv string
	var sessionSet, jsonOutput bool
	str := func(i *int, name string, dst *string) bool {
		if *i+1 >= len(args) {
			fmt.Fprintf(os.Stderr, "error: %s requires a value\n%s\n", name, sessionUsage)
			return false
		}
		*i++
		*dst = args[*i]
		return true
	}
	for i := 0; i < len(args); i++ {
		ok := true
		switch args[i] {
		case "--json":
			jsonOutput = true
		case "--session":
			ok = str(&i, "--session", &session)
			sessionSet = true
		case "--lock-db":
			ok = str(&i, "--lock-db", &lockDB)
		case "--guard-trail":
			ok = str(&i, "--guard-trail", &guardTrail)
		case "--pub-env":
			ok = str(&i, "--pub-env", &pubEnv)
		case "--lock-pub-env":
			ok = str(&i, "--lock-pub-env", &lockPubEnv)
		case "--guard-pub-env":
			ok = str(&i, "--guard-pub-env", &guardPubEnv)
		default:
			fmt.Fprintf(os.Stderr, "error: unknown flag %q for verify --session\n%s\n", args[i], sessionUsage)
			return 1
		}
		if !ok {
			return 1
		}
	}
	switch {
	case !sessionSet || session == "":
		fmt.Fprintf(os.Stderr, "error: --session requires a non-empty session id\n%s\n", sessionUsage)
		return 1
	case lockDB == "":
		fmt.Fprintf(os.Stderr, "error: --lock-db <path> is required (no discovery)\n%s\n", sessionUsage)
		return 1
	case guardTrail == "":
		fmt.Fprintf(os.Stderr, "error: --guard-trail <path> is required (no discovery)\n%s\n", sessionUsage)
		return 1
	case pubEnv != "" && (lockPubEnv != "" || guardPubEnv != ""):
		fmt.Fprintf(os.Stderr, "error: use either --pub-env, or both --lock-pub-env and --guard-pub-env, not both forms\n%s\n", sessionUsage)
		return 1
	case pubEnv == "" && (lockPubEnv == "" || guardPubEnv == ""):
		fmt.Fprintf(os.Stderr, "error: a public key is required for each chain: --pub-env <ENV>, or both --lock-pub-env and --guard-pub-env\n%s\n", sessionUsage)
		return 1
	}
	if pubEnv != "" {
		lockPubEnv, guardPubEnv = pubEnv, pubEnv
	}
	lockPub, err := loadPubFromEnv(lockPubEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: lock key: %v\n", err)
		return 1
	}
	guardPub, err := loadPubFromEnv(guardPubEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: guard key: %v\n", err)
		return 1
	}

	res := verifySession(session, lockDB, lockPub, guardTrail, guardPub)
	if jsonOutput {
		writeJSON(res)
	} else {
		printSessionResult(res)
	}
	return sessionExitCode(res.Verdict)
}

func sessionExitCode(verdict string) int {
	switch verdict {
	case sessionVerdictProtected:
		return 0
	case sessionVerdictTampered:
		return 2
	default:
		return 1
	}
}

// verifySession runs both chain checks and combines them.
func verifySession(session, lockDB string, lockPub ed25519.PublicKey, guardTrail string, guardPub ed25519.PublicKey) sessionVerifyResult {
	res := sessionVerifyResult{
		SessionID:    session,
		Lock:         verifyLockSession(lockDB, lockPub, session),
		Guard:        verifyGuardSession(guardTrail, guardPub, session),
		RollbackNote: sessionRollbackNote,
	}
	res.Verdict = combineSessionVerdicts(res.Lock, res.Guard)
	return res
}

// combineSessionVerdicts is PROTECTED only when both chains are INTACT with at
// least one session row and a verified tail; otherwise the worst failure.
func combineSessionVerdicts(chains ...sessionChainResult) string {
	worst, worstRank := "", 0
	for _, c := range chains {
		v := c.Verdict
		if v == chainVerdictIntact {
			// Belt and braces: INTACT must already imply both of these.
			switch {
			case c.Rows < 1:
				v = sessionVerdictNoRows
			case !c.TailVerified:
				v = sessionVerdictUnanchored
			default:
				continue
			}
		}
		rank, known := sessionFailRank[v]
		if !known {
			// A verdict this build does not know is never success.
			v, rank = sessionVerdictUnverifiable, sessionFailRank[sessionVerdictUnverifiable]
		}
		if rank > worstRank {
			worst, worstRank = v, rank
		}
	}
	if worst == "" {
		return sessionVerdictProtected
	}
	return worst
}

// verifyLockSession delegates to nocklock's pkg/receipt.
func verifyLockSession(dbPath string, pub ed25519.PublicKey, session string) sessionChainResult {
	c := sessionChainResult{Path: dbPath, KeyID: keyFingerprint(pub)}
	if fi, err := os.Stat(dbPath); err != nil {
		c.Verdict, c.Reason = sessionVerdictUnverifiable, fmt.Sprintf("cannot read lock db: %v", err)
		return c
	} else if !fi.Mode().IsRegular() {
		c.Verdict, c.Reason = sessionVerdictUnverifiable, "lock db is not a regular file"
		return c
	}
	r, err := receipt.VerifySession(dbPath, pub, session)
	c.Verdict = r.Verdict
	c.Rows = r.RowsChecked
	c.TailVerified = r.TailVerified
	c.TailReason = r.TailReason
	c.FirstBadRow = r.FirstBadRow
	c.Reason = r.Reason
	if err != nil {
		c.Verdict = sessionVerdictUnverifiable
		if c.Reason == "" {
			c.Reason = err.Error()
		}
	}
	if r.KeyID != "" && r.KeyID != c.KeyID {
		c.Verdict = sessionVerdictUnverifiable
		c.Reason = fmt.Sprintf("receipt key id %s does not match the lock key fingerprint %s", r.KeyID, c.KeyID)
	}
	return c
}

// verifyGuardSession verifies the WHOLE Guard trail with audit.VerifyEd25519
// (every line's signature, the chain, and the signed .hwm tail check), then
// selects the lines whose session_id equals session. The Guard verifier cannot
// yield UNSIGNED: an unsigned line is a chain break (TAMPERED) there.
func verifyGuardSession(path string, pub ed25519.PublicKey, session string) sessionChainResult {
	c := sessionChainResult{Path: path, KeyID: keyFingerprint(pub)}
	fi, err := os.Stat(path)
	if err != nil {
		c.Verdict, c.Reason = sessionVerdictUnverifiable, fmt.Sprintf("cannot read guard trail: %v", err)
		return c
	}
	if !fi.Mode().IsRegular() {
		c.Verdict, c.Reason = sessionVerdictUnverifiable, "guard trail is not a regular file"
		return c
	}

	n, verr := audit.VerifyEd25519(path, pub)
	c.EntriesVerified = n
	if verr != nil {
		c.Reason = verr.Error()
		if errors.Is(verr, audit.ErrTamper) {
			c.Verdict = sessionVerdictTampered
		} else {
			c.Verdict = sessionVerdictUnverifiable
		}
		return c
	}
	// VerifyEd25519 enforced the .hwm check. It passes a trail with no sidecar
	// only when the trail is empty, so require the sidecar explicitly.
	if hfi, herr := os.Stat(path + ".hwm"); herr == nil && hfi.Mode().IsRegular() && n > 0 {
		c.TailVerified = true
	} else {
		c.TailReason = "no signed .hwm sidecar: rows removed from the tail cannot be detected"
	}

	// Select the session's lines from the trail just verified.
	f, err := os.Open(path)
	if err != nil {
		c.Verdict, c.Reason = sessionVerdictUnverifiable, fmt.Sprintf("re-read guard trail: %v", err)
		return c
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), audit.MaxTrailLineBytes)
	line := 0
	for sc.Scan() {
		raw := sc.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		line++
		var ev audit.Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			c.Verdict, c.Reason = sessionVerdictTampered, fmt.Sprintf("line %d: invalid json on re-read: %v", line, err)
			return c
		}
		// The whole trail verified under one key, so a key_id naming any other
		// key is inconsistent on ANY line, not only this session's.
		if ev.KeyID != "" && ev.KeyID != c.KeyID {
			c.Verdict = sessionVerdictTampered
			c.Reason = fmt.Sprintf("line %d: key_id %s does not match the guard key fingerprint %s", line, ev.KeyID, c.KeyID)
			return c
		}
		if ev.SessionID != session {
			continue
		}
		c.Rows++
		if ev.Sig == "" {
			c.Verdict, c.Reason = sessionVerdictUnsigned, fmt.Sprintf("line %d of session %q carries no signature", line, session)
			return c
		}
	}
	if err := sc.Err(); err != nil {
		c.Verdict, c.Reason = sessionVerdictUnverifiable, fmt.Sprintf("re-read guard trail: %v", err)
		return c
	}
	if line != n {
		// The file changed between verification and selection.
		c.Verdict, c.Reason = sessionVerdictUnverifiable, fmt.Sprintf("guard trail changed during verification (%d lines verified, %d re-read)", n, line)
		return c
	}
	switch {
	case c.Rows == 0:
		c.Verdict, c.Reason = sessionVerdictNoRows, fmt.Sprintf("no lines for session %q", session)
	case !c.TailVerified:
		c.Verdict, c.Reason = sessionVerdictUnanchored, c.TailReason
	default:
		c.Verdict = chainVerdictIntact
	}
	return c
}

func printSessionResult(res sessionVerifyResult) {
	fmt.Printf("Session %s\n", res.SessionID)
	tail := func(c sessionChainResult, what string) string {
		if c.TailVerified {
			return "tail verified (" + what + ")"
		}
		return "tail NOT verified"
	}
	l := res.Lock
	fmt.Printf("  NockLock  %-12s %d rows, %s  %s\n", l.Verdict, l.Rows, tail(l, "signed chain_head"), l.Path)
	fmt.Printf("            key %s\n", l.KeyID)
	if l.Reason != "" {
		fmt.Printf("            %s\n", l.Reason)
	}
	g := res.Guard
	fmt.Printf("  NockGuard %-12s %d of %d entries, %s  %s\n", g.Verdict, g.Rows, g.EntriesVerified, tail(g, "signed .hwm"), g.Path)
	fmt.Printf("            key %s\n", g.KeyID)
	if g.Reason != "" {
		fmt.Printf("            %s\n", g.Reason)
	}
	fmt.Println(res.RollbackNote)
	fmt.Printf("VERDICT: %s\n", res.Verdict)
}
