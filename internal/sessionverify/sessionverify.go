// Package sessionverify is the one verifier behind `nockguard verify --session`
// and the Live Wall's per-session proof badge, so the two can never disagree.
package sessionverify

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
// chain_head anchors the walked chain; Guard: the signed .hwm checkpoint
// covers every entry in the trail). Otherwise the worst per-chain verdict by
// TAMPERED > UNVERIFIABLE > UNSIGNED > NO_ROWS > UNANCHORED.
// Exit codes follow `verify`: 0 = PROTECTED, 2 = TAMPERED, 1 = anything else.

const (
	VerdictProtected    = "PROTECTED"
	VerdictTampered     = "TAMPERED"
	VerdictUnverifiable = "UNVERIFIABLE"
	VerdictUnsigned     = "UNSIGNED"
	VerdictNoRows       = "NO_ROWS"
	VerdictUnanchored   = "UNANCHORED"
	ChainVerdictIntact  = "INTACT"
)

// RollbackNote is printed on every run, success or not: the residual
// this command cannot see.
const RollbackNote = "Not checked here: a rollback of a whole chain together with its signed head " +
	"(NockLock chain_head, NockGuard .hwm) to an earlier genuine state passes every local check. " +
	"Only `nocklock verify --against-remote-anchor` detects that, and only for the NockLock chain; " +
	"this command consults no anchor."

// failRank orders failing verdicts, worst first.
var failRank = map[string]int{
	VerdictTampered:     5,
	VerdictUnverifiable: 4,
	VerdictUnsigned:     3,
	VerdictNoRows:       2,
	VerdictUnanchored:   1,
}

type ChainResult struct {
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

type Result struct {
	Verdict      string      `json:"verdict"`
	SessionID    string      `json:"session_id"`
	Lock         ChainResult `json:"lock"`
	Guard        ChainResult `json:"guard"`
	RollbackNote string      `json:"rollback_note"`
}

func KeyFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// Verify runs both chain checks and combines them.
func Verify(session, lockDB string, lockPub ed25519.PublicKey, guardTrail string, guardPub ed25519.PublicKey) Result {
	return NewResult(session, VerifyLock(lockDB, lockPub, session), verifyGuard(guardTrail, guardPub, session))
}

// NewResult combines one Lock and one Guard chain result into a session verdict.
// The wall holds its own Guard bytes, builds the chain results itself and
// combines them here, so there is one combination rule.
func NewResult(session string, lock, guard ChainResult) Result {
	res := Result{SessionID: session, Lock: lock, Guard: guard, RollbackNote: RollbackNote}
	res.Verdict = combine(res.Lock, res.Guard)
	return res
}

// combine is PROTECTED only when both chains are INTACT with at
// least one session row and a verified tail; otherwise the worst failure.
func combine(chains ...ChainResult) string {
	worst, worstRank := "", 0
	for _, c := range chains {
		v := c.Verdict
		if v == ChainVerdictIntact {
			// Belt and braces: INTACT must already imply both of these.
			switch {
			case c.Rows < 1:
				v = VerdictNoRows
			case !c.TailVerified:
				v = VerdictUnanchored
			default:
				continue
			}
		}
		rank, known := failRank[v]
		if !known {
			// A verdict this build does not know is never success.
			v, rank = VerdictUnverifiable, failRank[VerdictUnverifiable]
		}
		if rank > worstRank {
			worst, worstRank = v, rank
		}
	}
	if worst == "" {
		return VerdictProtected
	}
	return worst
}

// RequireRegularFile refuses a missing path, a symlink, or any non-regular
// file. The Lock DB path gets the same rule the Guard inputs get.
func RequireRegularFile(path string) error {
	fi, err := os.Lstat(path)
	switch {
	case err != nil:
		return err
	case fi.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("%s is a symlink; refusing to follow it", path)
	case !fi.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file", path)
	}
	return nil
}

// VerifyLock is the Lock chain check of one session against the DB at dbPath;
// it delegates to nocklock's pkg/receipt.
func VerifyLock(dbPath string, pub ed25519.PublicKey, session string) ChainResult {
	c := ChainResult{Path: dbPath, KeyID: KeyFingerprint(pub)}
	if err := RequireRegularFile(dbPath); err != nil {
		c.Verdict, c.Reason = VerdictUnverifiable, fmt.Sprintf("lock db: %v", err)
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
		c.Verdict = VerdictUnverifiable
		if c.Reason == "" {
			c.Reason = err.Error()
		}
	}
	if r.KeyID != "" && r.KeyID != c.KeyID {
		c.Verdict = VerdictTampered
		c.Reason = fmt.Sprintf("receipt key id %s does not match the lock key fingerprint %s", r.KeyID, c.KeyID)
	}
	return c
}

// Guard snapshot caps. The trail cap is a multiple of the per-line cap the
// verifier already enforces (audit.MaxTrailLineBytes); the .hwm sidecar is a
// single small JSON object.
const (
	guardTrailSnapshotCap = 64 * audit.MaxTrailLineBytes
	guardHWMSnapshotCap   = 64 * 1024
)

// GuardSnapshotOpen opens a Guard file for the one snapshot read. A package
// var only so tests can count opens; production is os.Open.
var GuardSnapshotOpen = os.Open

// readGuardSnapshot reads path into memory exactly once. It refuses symlinks
// and non-regular files, and refuses a file swapped between the Lstat and the
// open. exists is false (with a nil error) only when path does not exist.
func readGuardSnapshot(path string, limit int64) (data []byte, exists bool, err error) {
	lfi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if lfi.Mode()&os.ModeSymlink != 0 {
		return nil, true, fmt.Errorf("%s is a symlink; refusing to follow it", path)
	}
	if !lfi.Mode().IsRegular() {
		return nil, true, fmt.Errorf("%s is not a regular file", path)
	}
	f, err := GuardSnapshotOpen(path)
	if err != nil {
		return nil, true, err
	}
	defer f.Close()
	ofi, err := f.Stat()
	if err != nil {
		return nil, true, err
	}
	if !os.SameFile(lfi, ofi) {
		return nil, true, fmt.Errorf("%s was replaced while being opened", path)
	}
	data, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, true, err
	}
	if int64(len(data)) > limit {
		return nil, true, fmt.Errorf("%s exceeds the %d-byte snapshot cap", path, limit)
	}
	if data == nil {
		data = []byte{}
	}
	return data, true, nil
}

// ReadGuard snapshots the Guard trail and its .hwm sidecar ONCE each. The
// trail path is never reopened, so nothing can be swapped between verification
// and selection. A missing sidecar yields a nil hwm; a missing trail is an error.
func ReadGuard(path string, trailLimit int64) (trail, hwm []byte, err error) {
	// The .hwm is snapshotted BEFORE the trail. audit.Auditor.Record appends
	// the entry and only then advances the .hwm, so a checkpoint read first
	// always describes a prefix of any trail read after it. A concurrent append
	// then reads as UNANCHORED (entries beyond the checkpoint), never PROTECTED.
	// Reading in the other order lets a genuine append between the two reads
	// pair a newer checkpoint with an older trail (a spurious TAMPERED).
	hwm, _, err = readGuardSnapshot(path+".hwm", guardHWMSnapshotCap)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read guard .hwm sidecar: %w", err)
	}
	trail, exists, err := readGuardSnapshot(path, trailLimit)
	if err == nil && !exists {
		err = fmt.Errorf("%s does not exist", path)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read guard trail: %w", err)
	}
	return trail, hwm, nil
}

// verifyGuard reads the Guard files once (ReadGuard) and hands those bytes to
// VerifyGuardSnapshot.
func verifyGuard(path string, pub ed25519.PublicKey, session string) ChainResult {
	trail, hwm, err := ReadGuard(path, guardTrailSnapshotCap)
	if err != nil {
		return ChainResult{Path: path, KeyID: KeyFingerprint(pub), Verdict: VerdictUnverifiable, Reason: err.Error()}
	}
	c := VerifyGuardSnapshot(trail, hwm, pub, session)
	c.Path = path
	return c
}

// GuardCheck is one Guard trail snapshot verified once. Session then selects
// any number of sessions' lines from the same bytes without re-walking the
// whole trail.
type GuardCheck struct {
	trail []byte
	base  ChainResult // Verdict is non-empty when the whole-trail check already failed
}

// CheckGuard verifies the WHOLE trail snapshot with audit.VerifyEd25519Bytes
// (every line's signature, the chain, and the signed .hwm tail check; hwm is
// nil when the sidecar is absent).
func CheckGuard(trail, hwm []byte, pub ed25519.PublicKey) *GuardCheck {
	return &GuardCheck{trail: trail, base: checkGuardWhole(trail, hwm, pub)}
}

// VerifyGuardSnapshot is CheckGuard followed by Session for one session.
func VerifyGuardSnapshot(trail, hwm []byte, pub ed25519.PublicKey, session string) ChainResult {
	return CheckGuard(trail, hwm, pub).Session(session)
}

func checkGuardWhole(trail, hwm []byte, pub ed25519.PublicKey) ChainResult {
	c := ChainResult{KeyID: KeyFingerprint(pub)}
	n, verr := audit.VerifyEd25519Bytes(trail, hwm, pub)
	c.EntriesVerified = n
	if verr != nil {
		c.Reason = verr.Error()
		if errors.Is(verr, audit.ErrTamper) {
			c.Verdict = VerdictTampered
		} else {
			c.Verdict = VerdictUnverifiable
		}
		return c
	}
	// The verifier already checked the .hwm signature, rejected a checkpoint
	// count above the entries present (truncation), and matched the entry at
	// the checkpoint's count. The tail is verified ONLY when the checkpoint
	// covers every entry in the snapshot: entries past it (a writer mid-append,
	// or a crash before the .hwm update) are signed but unanchored, so rows
	// removed from that suffix could not be detected.
	switch {
	case hwm == nil || n == 0:
		c.TailReason = "no signed .hwm sidecar: rows removed from the tail cannot be detected"
	default:
		var mark struct {
			Count int `json:"count"`
		}
		if err := json.Unmarshal(bytes.TrimSpace(hwm), &mark); err != nil {
			c.Verdict, c.Reason = VerdictUnverifiable, fmt.Sprintf("guard .hwm: %v", err)
			return c
		}
		switch {
		case mark.Count == n:
			c.TailVerified = true
		case mark.Count < n:
			c.TailReason = fmt.Sprintf("%d entries beyond the signed checkpoint (count %d); re-run once the writer is idle", n-mark.Count, mark.Count)
		default:
			// Unreachable: the verifier reports this as truncation. Never pass it.
			c.Verdict, c.Reason = VerdictTampered, fmt.Sprintf("signed checkpoint count %d exceeds the %d entries in the trail", mark.Count, n)
			return c
		}
	}
	return c
}

// Session selects the session's lines from the exact bytes CheckGuard verified,
// split the same way the verifier split them. The Guard verifier cannot yield
// UNSIGNED: an unsigned line is a chain break (TAMPERED) there.
func (g *GuardCheck) Session(session string) ChainResult {
	c := g.base
	if c.Verdict != "" {
		return c
	}
	trail := g.trail
	sc := bufio.NewScanner(bytes.NewReader(trail))
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
			c.Verdict, c.Reason = VerdictTampered, fmt.Sprintf("line %d: invalid json: %v", line, err)
			return c
		}
		// The whole trail verified under one key, so a key_id naming any other
		// key is inconsistent on ANY line, not only this session's.
		if ev.KeyID != "" && ev.KeyID != c.KeyID {
			c.Verdict = VerdictTampered
			c.Reason = fmt.Sprintf("line %d: key_id %s does not match the guard key fingerprint %s", line, ev.KeyID, c.KeyID)
			return c
		}
		if ev.SessionID != session {
			continue
		}
		c.Rows++
		if ev.Sig == "" {
			c.Verdict, c.Reason = VerdictUnsigned, fmt.Sprintf("line %d of session %q carries no signature", line, session)
			return c
		}
	}
	if err := sc.Err(); err != nil {
		c.Verdict, c.Reason = VerdictUnverifiable, fmt.Sprintf("scan guard snapshot: %v", err)
		return c
	}
	switch {
	case c.Rows == 0:
		c.Verdict, c.Reason = VerdictNoRows, fmt.Sprintf("no lines for session %q", session)
	case !c.TailVerified:
		c.Verdict, c.Reason = VerdictUnanchored, c.TailReason
	default:
		c.Verdict = ChainVerdictIntact
	}
	return c
}
