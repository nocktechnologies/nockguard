package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/nocktechnologies/nockguard/internal/sessionverify"
)

// maxBadgeSessions bounds how many recent sessions get a proof badge. Each
// badge is a walk of the Lock chain, so the cap bounds the work per refresh.
const maxBadgeSessions = 10

// A refresh (Lock copy, Lock chain walk, Guard read and verify) is not repeated
// within sessionReverify, and after that only when a log's size or mtime moved
// (the head changed). Because size and mtime can be preserved by an attacker, a
// refresh is also forced every forcedReverify whether or not anything moved, so
// tampering shows within that bound. The page polls /sessions every 5 s.
const (
	sessionReverify = 4 * time.Second
	forcedReverify  = 60 * time.Second
)

// demoSessionID is the synthetic session --demo shows. It is never signed.
const demoSessionID = "demo-session"

// fileSig is a cheap change detector for a log file: size and mtime, or "-"
// when absent.
func fileSig(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return "-"
	}
	return fmt.Sprintf("%d/%d", fi.Size(), fi.ModTime().UnixNano())
}

// walSig is fileSig for a SQLite -wal file, where an empty file counts as
// absent: merely opening the log (as every refresh does) can create one, and
// that must not read as the log having changed.
func walSig(path string) string {
	if fi, err := os.Stat(path); err == nil && fi.Size() == 0 {
		return "-"
	}
	return fileSig(path)
}

// mergeByTime merges two oldest-first event lists into one oldest-first list.
// It does not truncate: each source is already bounded to maxWindow, so a
// source can never displace the other's rows. An unparseable timestamp sorts as
// the zero time, so the stable sort keeps such rows in arrival order rather
// than dropping them.
func mergeByTime(a, b []event) []event {
	if len(b) == 0 {
		return a
	}
	evs := append(append([]event{}, a...), b...)
	ts := func(e event) time.Time { t, _ := time.Parse(time.RFC3339, e.Ts); return t }
	sort.SliceStable(evs, func(i, j int) bool { return ts(evs[i]).Before(ts(evs[j])) })
	return evs
}

// lastWindow keeps the newest maxWindow events of an oldest-first list.
func lastWindow(evs []event) []event {
	if len(evs) > maxWindow {
		return evs[len(evs)-maxWindow:]
	}
	return evs
}

// wallView is ONE snapshot of everything the wall shows about a refresh. The
// Guard trail bytes were read once and verified once; the Lock rows were read
// from the single private copy the Lock chain was verified on. The badges, the
// replayed stream, the pulse and the export are all rendered from these slices,
// so nothing is marked verified by a check that read different bytes.
type wallView struct {
	at       time.Time
	sig      string       // log heads at read time; see headSig
	guardEvs []event      // Guard window decoded from the verified trail bytes (auditLine set)
	rep      verifyReport // the Guard chain walk over those same bytes
	lock     lockView     // Lock rows, and the badges verified over them
}

// lockView is the Lock half of a wallView.
type lockView struct {
	events []event                // Lock rows read from the verified copy (nil when err != nil)
	badges []sessionverify.Result // newest session first, at most maxBadgeSessions
	err    error                  // the copy could not be taken (or the log is too large)
}

// status is the export header value: "ok" or "unavailable" (no Lock rows were
// verified, so none are marked verified).
func (v lockView) status() string {
	if v.err != nil {
		return "unavailable"
	}
	return "ok"
}

// verdicts maps each badged session id to its verdict.
func (v lockView) verdicts() map[string]string {
	out := map[string]string{}
	for _, s := range v.badges {
		out[s.SessionID] = s.Verdict
	}
	return out
}

// windowEvents is the working window (pulse, unsigned export) of the current
// snapshot.
func (b *broker) windowEvents() []event {
	if b.demo {
		b.mu.Lock()
		defer b.mu.Unlock()
		return append([]event(nil), b.demoEvents...)
	}
	return lastWindow(b.currentView().events())
}

// events is the working window of a view: Guard decisions and Lock fence events
// merged oldest-first, each source bounded to maxWindow so neither can displace
// the other.
func (v *wallView) events() []event { return mergeByTime(v.guardEvs, v.lock.events) }

// headSig is the cheap head-change detector over every file a view reads.
func (b *broker) headSig() string {
	sig := fileSig(b.auditPath) + fileSig(b.auditPath+".hwm")
	if b.lockDB != "" {
		sig += fileSig(b.lockDB) + walSig(b.lockDB+"-wal")
	}
	return sig
}

// currentView returns the cached snapshot, building a new one when it is due.
// Callers share one build; the build runs outside smu, so readers of the cache
// never wait on it.
func (b *broker) currentView() *wallView { return b.getView(false, true) }

// freshView builds a new snapshot for a browser connecting (replay), which must
// see every row recorded so far, not a view up to a refresh interval old. A
// connect that arrives while a build runs shares it.
func (b *broker) freshView() *wallView { return b.getView(true, true) }

// exportView always builds its own snapshot: an export never reuses a build
// that started before it was asked for.
func (b *broker) exportView() *wallView { return b.getView(true, false) }

// viewQueued is a test seam: called after a caller read b.builds, before it waits
// for the build lock.
var viewQueued = func() {}

func (b *broker) getView(force, share bool) *wallView {
	sig := b.headSig()
	fresh := func() (*wallView, bool) {
		b.smu.Lock()
		defer b.smu.Unlock()
		v := b.view
		if v == nil || force {
			return nil, false
		}
		age := time.Since(v.at)
		return v, age < sessionReverify || (age < forcedReverify && v.sig == sig)
	}
	if v, ok := fresh(); ok {
		return v
	}
	b.smu.Lock()
	seen := b.builds
	b.smu.Unlock()
	viewQueued()
	b.lmu.Lock()
	defer b.lmu.Unlock()
	b.smu.Lock()
	reuse, cur := share && b.builds != seen, b.view
	b.smu.Unlock()
	if reuse { // a build ran while this caller waited: share it, even for a forced refresh (not for an export)
		return cur
	}
	if v, ok := fresh(); ok {
		return v
	}
	v := b.buildView(b.readGuard())
	v.sig = sig
	b.smu.Lock()
	b.view = v
	b.builds++
	b.smu.Unlock()
	return v
}

// guardRead is the Guard half of a snapshot: the trail and checkpoint bytes read
// once, or the reason they could not be.
type guardRead struct {
	trail, hwm []byte
	err        error
	// events is set instead of trail when no key is configured (nothing to
	// verify) or the trail could not be held whole (err set): the window is
	// streamed, and never marked verified.
	events []event
}

// readGuard reads the live Guard trail once, within the wall's size cap.
func (b *broker) readGuard() guardRead {
	if b.auditPath == "" {
		return guardRead{}
	}
	if !b.verifier.enabled() {
		return guardRead{events: loadEvents(b.auditPath)}
	}
	trail, hwm, err := sessionverify.ReadGuard(b.auditPath, b.exportTrailLimit)
	if err != nil {
		return guardRead{err: err, events: loadEvents(b.auditPath)}
	}
	return guardRead{trail: trail, hwm: hwm}
}

// buildView builds a snapshot from Guard bytes the caller already holds, so the
// signed export (which captures them under its own ordering rules) and the
// cached path share one implementation.
func (b *broker) buildView(g guardRead) *wallView {
	v := &wallView{at: time.Now()}
	var gc *sessionverify.GuardCheck
	switch {
	case g.err != nil:
		v.guardEvs = g.events
		v.rep = verifyReport{
			Status:         statusUnavailable,
			Verdict:        "UNAVAILABLE",
			Detail:         strptr(g.err.Error()),
			LastVerifiedAt: v.at.Format(time.RFC3339),
		}
		if b.verifier != nil {
			v.rep.PublicKeySource = b.verifier.pubSource
		}
	case g.events != nil:
		v.guardEvs = g.events
		v.rep = b.verifier.verifyBytes(nil, nil) // unconfigured: nothing to verify
	default:
		v.guardEvs = loadEventsFromBytes(g.trail)
		v.rep = b.verifier.verifyBytes(g.trail, g.hwm)
		if pub := b.guardPub(); len(pub) != 0 && g.trail != nil {
			gc = sessionverify.CheckGuard(g.trail, g.hwm, pub)
		}
	}
	if b.lockDB != "" {
		v.lock = b.buildLockView(v.guardEvs, gc, g.err)
	}
	return v
}

// guardPub is the Ed25519 key the Guard chain is verified under, if any.
func (b *broker) guardPub() ed25519.PublicKey {
	if b.verifier != nil && b.verifier.mode == modeEd25519 {
		return b.verifier.pub
	}
	return nil
}

// buildLockView copies the Lock DB once, reads the fence rows from that copy,
// and verifies the most recent sessions (in the Guard window plus the Lock rows)
// against the same copy, with the Guard side checked on the caller's bytes.
func (b *broker) buildLockView(guardEvs []event, gc *sessionverify.GuardCheck, guardErr error) lockView {
	snap, err := snapshotLock(b.lockDB)
	var big *tooLargeError
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Not created yet: the wall waits for it, so there is nothing to badge.
		return lockView{err: err, badges: []sessionverify.Result{}}
	case errors.As(err, &big):
		// No snapshot, no Lock rows: nothing is shown that was not verified.
		return b.unverifiedLockView(guardEvs, err)
	case err != nil:
		return lockView{err: err, badges: []sessionverify.Result{b.unverifiable("lock-db", err)}}
	}
	defer snap.Close()
	v := lockView{events: loadLockEvents(snap.Path), badges: []sessionverify.Result{}}
	unparsed := map[string]int{}
	for _, ev := range v.events {
		if ev.Decision == decisionUnparseable {
			unparsed[ev.Session]++
		}
	}
	for _, s := range recentSessions(mergeByTime(guardEvs, v.events)) {
		r := b.verifySessionBadge(s, snap, gc, guardErr)
		// An unparseable row of this session (or of an unknown one, which could
		// belong to any) was never checked: the badge cannot be better than that.
		if n := unparsed[s] + unparsed[""]; n > 0 && r.Verdict != sessionverify.VerdictTampered {
			r.Verdict = sessionverify.VerdictUnverifiable
			if r.Lock.Verdict != sessionverify.VerdictTampered {
				r.Lock.Verdict = sessionverify.VerdictUnverifiable
				r.Lock.Reason = fmt.Sprintf("%d unparseable fence row(s) in the Lock log could not be verified", n)
			}
		}
		v.badges = append(v.badges, r)
	}
	return v
}

// unverifiedLockView is the Lock half when the log is not verified at all: no
// rows, and every recent Guard session's badge carries the reason.
func (b *broker) unverifiedLockView(guardEvs []event, why error) lockView {
	v := lockView{err: why, badges: []sessionverify.Result{}}
	for _, s := range recentSessions(guardEvs) {
		v.badges = append(v.badges, b.unverifiable(s, why))
	}
	return v
}

// unverifiable is a badge for a session whose Lock log was not verified, and why.
func (b *broker) unverifiable(session string, why error) sessionverify.Result {
	r := sessionverify.Result{Verdict: sessionverify.VerdictUnverifiable, SessionID: session, RollbackNote: sessionverify.RollbackNote}
	r.Lock = sessionverify.ChainResult{Path: b.lockDB, Verdict: sessionverify.VerdictUnverifiable, Reason: why.Error()}
	return r
}

// recentSessions lists the session ids of an oldest-first window, newest first,
// at most maxBadgeSessions.
func recentSessions(evs []event) []string {
	var out []string
	seen := map[string]bool{}
	for i := len(evs) - 1; i >= 0 && len(out) < maxBadgeSessions; i-- {
		if s := evs[i].Session; s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// exportRowVerification is the export receipt for one row. A Guard row uses the
// chain walk; a Lock row is "verified" only when its whole session badge is
// PROTECTED, "failed" when TAMPERED, and "unsigned" otherwise, including a
// session outside the maxBadgeSessions most recent (not covered, not checked).
func exportRowVerification(rep verifyReport, verdicts map[string]string, ev event) string {
	if ev.Source != sourceLock {
		return exportVerification(rep, ev.auditLine)
	}
	switch verdicts[ev.Session] {
	case sessionverify.VerdictProtected:
		return "verified"
	case sessionverify.VerdictTampered:
		return "failed"
	}
	return "unsigned"
}

// sessionBadges returns one proof result per recent session, newest first,
// from the current snapshot.
func (b *broker) sessionBadges() []sessionverify.Result {
	if b.demo {
		r := sessionverify.Result{Verdict: sessionverify.VerdictUnsigned, SessionID: demoSessionID}
		r.Lock.Reason = "synthetic demo data: nothing here is signed or verified"
		return []sessionverify.Result{r}
	}
	if b.lockDB == "" {
		return []sessionverify.Result{}
	}
	return b.currentView().lock.badges
}

// verifySessionBadge is the `nockguard verify --session` verdict for one
// session: the Lock chain on the snapshot copy and the Guard chain on the
// snapshot bytes. A missing key on either side is UNVERIFIABLE: the badge is
// never green without both keys, and the wall never guesses one.
func (b *broker) verifySessionBadge(session string, snap *lockSnapshot, gc *sessionverify.GuardCheck, guardErr error) sessionverify.Result {
	guardPub := b.guardPub()
	if len(b.lockPub) == 0 || len(guardPub) == 0 {
		r := sessionverify.Result{Verdict: sessionverify.VerdictUnverifiable, SessionID: session, RollbackNote: sessionverify.RollbackNote}
		r.Lock = sessionverify.ChainResult{Path: b.lockDB, Verdict: sessionverify.VerdictUnverifiable}
		r.Guard = sessionverify.ChainResult{Path: b.auditPath, Verdict: sessionverify.VerdictUnverifiable}
		if len(b.lockPub) == 0 {
			r.Lock.Reason = "no NockLock public key configured (--lock-pub-env)"
		} else {
			r.Lock.KeyID = sessionverify.KeyFingerprint(b.lockPub)
			r.Lock.Reason = "not checked: the NockGuard key is missing, and one verdict needs both chains"
		}
		if len(guardPub) == 0 {
			r.Guard.Reason = "no NockGuard Ed25519 public key configured (--verify-ed25519-pub-env)"
		} else {
			r.Guard.KeyID = sessionverify.KeyFingerprint(guardPub)
			r.Guard.Reason = "not checked: the NockLock key is missing, and one verdict needs both chains"
		}
		return r
	}
	lock := sessionverify.VerifyLock(snap.Path, b.lockPub, session)
	lock.Path, lock.Reason, lock.TailReason = b.lockDB, snap.scrub(lock.Reason), snap.scrub(lock.TailReason)
	var guard sessionverify.ChainResult
	if gc == nil {
		guard = sessionverify.ChainResult{KeyID: sessionverify.KeyFingerprint(guardPub), Verdict: sessionverify.VerdictUnverifiable, Reason: "guard trail unavailable"}
		if guardErr != nil {
			guard.Reason = guardErr.Error()
		}
	} else {
		guard = gc.Session(session)
	}
	guard.Path = b.auditPath
	return sessionverify.NewResult(session, lock, guard)
}

// handleSessions serves the per-session proof badges as JSON.
func (b *broker) handleSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(b.sessionBadges())
}
