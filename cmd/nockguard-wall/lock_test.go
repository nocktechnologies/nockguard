package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/sessionverify"
)

const lockSessA = "session-a"

// lockWall is a broker over a copy of nocklock's genuine signed events.db
// (testdata, byte copy of the fixture `nockguard verify --session` is tested
// with) and a freshly signed Guard trail. Session session-a has one Lock fence
// row (file_blocked /etc/shadow) and two Guard rows.
type lockWall struct {
	b        *broker
	lockDB   string
	guardPub ed25519.PublicKey
}

func newLockWall(t *testing.T) lockWall {
	t.Helper()
	dir := t.TempDir()
	db, err := os.ReadFile(filepath.Join("testdata", "nocklock-signed.db"))
	if err != nil {
		t.Fatal(err)
	}
	lockDB := filepath.Join(dir, "events.db")
	if err := os.WriteFile(lockDB, db, 0o600); err != nil {
		t.Fatal(err)
	}
	pubHex, err := os.ReadFile(filepath.Join("testdata", "nocklock-signed.pub"))
	if err != nil {
		t.Fatal(err)
	}
	lockPub, err := audit.PublicKeyFromHex(strings.TrimSpace(string(pubHex)))
	if err != nil {
		t.Fatal(err)
	}
	gpub, gpriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	trail := filepath.Join(dir, "coder.audit.jsonl")
	a, err := audit.New(trail, audit.WithEd25519Key(gpriv))
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range []audit.Event{
		{Agent: "coder", Tool: "Read", Decision: "allow", SessionID: lockSessA},
		{Agent: "coder", Tool: "Bash", Decision: "deny", Reason: "policy", SessionID: lockSessA},
	} {
		if err := a.Record(ev); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	b := newBroker()
	b.auditPath = trail
	b.lockDB = lockDB
	b.lockPub = lockPub
	b.verifier = &verifier{mode: modeEd25519, pub: gpub}
	return lockWall{b: b, lockDB: lockDB, guardPub: gpub}
}

func (w lockWall) badges(t *testing.T) []sessionverify.Result {
	t.Helper()
	w.b.view = nil // drop the snapshot: each call is a fresh verification
	rec := httptest.NewRecorder()
	w.b.handleSessions(rec, httptest.NewRequest(http.MethodGet, "/sessions", nil))
	var out []sessionverify.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode /sessions: %v\n%s", err, rec.Body.String())
	}
	return out
}

func (w lockWall) badge(t *testing.T, session string) sessionverify.Result {
	t.Helper()
	for _, s := range w.badges(t) {
		if s.SessionID == session {
			return s
		}
	}
	t.Fatalf("no badge for %s", session)
	return sessionverify.Result{}
}

func TestLockRowsRender(t *testing.T) {
	w := newLockWall(t)
	var buf bytes.Buffer
	w.b.replayHistory(&buf)
	var lockRows, guardRows int
	for _, ln := range strings.Split(buf.String(), "\n\n") {
		if !strings.HasPrefix(ln, "data: ") {
			continue
		}
		var ev event
		if err := json.Unmarshal([]byte(strings.TrimPrefix(ln, "data: ")), &ev); err != nil {
			t.Fatal(err)
		}
		switch ev.Source {
		case sourceLock:
			lockRows++
			if ev.Decision != "block" || ev.Tool != "file: /etc/shadow" || ev.Session != lockSessA || ev.Severity != "critical" { // /etc/shadow is a critical target
				t.Fatalf("lock row mapped wrong: %+v", ev)
			}
		case sourceGuard:
			guardRows++
		}
	}
	// Lifecycle rows (session_start/end) are not fence events and stay off the wall.
	if lockRows != 1 || guardRows != 2 {
		t.Fatalf("replay: %d LOCK / %d GUARD rows, want 1 / 2\n%s", lockRows, guardRows, buf.String())
	}
	// The same rows feed the pulse aggregate.
	if p := computePulse(w.b.windowEvents(), "", "", "", nil, nil); p.Total != 3 {
		t.Fatalf("pulse total = %d, want 3", p.Total)
	}
}

func TestSessionBadgeProtectedThenTamperedOnEditedLockRow(t *testing.T) {
	w := newLockWall(t)
	got := w.badge(t, lockSessA)
	if got.Verdict != sessionverify.VerdictProtected {
		t.Fatalf("clean session = %s (lock: %s %s, guard: %s %s), want PROTECTED",
			got.Verdict, got.Lock.Verdict, got.Lock.Reason, got.Guard.Verdict, got.Guard.Reason)
	}
	if got.Lock.KeyID != sessionverify.KeyFingerprint(w.b.lockPub) || got.Guard.KeyID != sessionverify.KeyFingerprint(w.guardPub) {
		t.Fatalf("badge must carry both key fingerprints: %+v", got)
	}

	// Edit ONE Lock row the way a file-level attacker would: same size, and the
	// original mtime restored. No size/mtime change detector can see this.
	fi0, err := os.Stat(w.lockDB)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", w.lockDB)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := db.Exec(`UPDATE events SET detail = '/etc/shadoX' WHERE id = 3`); err != nil {
		t.Fatal(err)
	} else if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("edited %d rows, want 1", n)
	}
	db.Close()
	if err := os.Chtimes(w.lockDB, fi0.ModTime(), fi0.ModTime()); err != nil {
		t.Fatal(err)
	}
	if fi1, _ := os.Stat(w.lockDB); fi1.Size() != fi0.Size() || !fi1.ModTime().Equal(fi0.ModTime()) {
		t.Skip("could not preserve size and mtime on this filesystem")
	}

	// Inside the re-verify interval the cached verdict stands...
	w.b.view.at = time.Now()
	if cached := w.b.sessionBadges(); len(cached) == 0 || cached[0].Verdict != sessionverify.VerdictProtected {
		t.Fatalf("cache should hold PROTECTED inside the interval: %+v", cached)
	}
	// ...and once the forced interval lapses, the unchanged-looking file is
	// re-verified (size and mtime say nothing moved).
	w.b.view.at = time.Now().Add(-2 * forcedReverify)
	got = w.badge(t, lockSessA)
	if got.Verdict != sessionverify.VerdictTampered || got.Lock.Verdict != sessionverify.VerdictTampered {
		t.Fatalf("after one edited Lock row = %s (lock %s), want TAMPERED", got.Verdict, got.Lock.Verdict)
	}
	// Export receipts follow the badge: a tampered session's Lock rows are "failed".
	lockRow := event{Source: sourceLock, Session: lockSessA}
	if v := exportRowVerification(verifyReport{}, w.b.buildLockView(nil, nil, nil).verdicts(), lockRow); v != "failed" {
		t.Fatalf("export verification for tampered Lock row = %q, want failed", v)
	}
}

func TestSessionBadgeMissingKeyIsUnverifiable(t *testing.T) {
	for name, strip := range map[string]func(*lockWall){
		"no lock key":  func(w *lockWall) { w.b.lockPub = nil },
		"no guard key": func(w *lockWall) { w.b.verifier = &verifier{mode: modeNone} },
	} {
		t.Run(name, func(t *testing.T) {
			w := newLockWall(t)
			strip(&w)
			got := w.badge(t, lockSessA)
			if got.Verdict != sessionverify.VerdictUnverifiable {
				t.Fatalf("verdict = %s, want UNVERIFIABLE (a missing key is never green)", got.Verdict)
			}
			if v := exportRowVerification(verifyReport{}, w.b.buildLockView(nil, nil, nil).verdicts(), event{Source: sourceLock, Session: lockSessA}); v != "unsigned" {
				t.Fatalf("export verification = %q, want unsigned", v)
			}
		})
	}
}

func TestLockDBIsNeverWritten(t *testing.T) {
	w := newLockWall(t)
	hash := func() (string, time.Time) {
		data, err := os.ReadFile(w.lockDB)
		if err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(w.lockDB)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:]), fi.ModTime()
	}
	h0, m0 := hash()
	time.Sleep(20 * time.Millisecond)

	var buf bytes.Buffer
	w.b.replayHistory(&buf)
	_ = loadLockEvents(w.lockDB)
	_, _ = pollLock(w.lockDB, -1, w.b)
	_, _ = pollLock(w.lockDB, 0, w.b)
	_ = w.badges(t)
	_ = w.b.windowEvents()

	if h1, m1 := hash(); h1 != h0 || !m1.Equal(m0) {
		t.Fatalf("lock db changed under the wall: sha256 %s -> %s, mtime %v -> %v", h0, h1, m0, m1)
	}
	// And the connection itself refuses writes.
	d, err := openLockDB(w.lockDB)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := d.Exec(`DELETE FROM events`); err == nil {
		t.Fatal("wall's lock connection accepted a write")
	}
}

func TestPollLockSeesAppendsAndReverifies(t *testing.T) {
	w := newLockWall(t)
	c := make(chan event, 8)
	w.b.register(c)
	last, _ := pollLock(w.lockDB, -1, w.b) // adopt the current tail, emit nothing
	if len(c) != 0 {
		t.Fatalf("first poll emitted %d rows, want none (history is replayed per client)", len(c))
	}
	before := w.badge(t, lockSessA)
	if before.Verdict != sessionverify.VerdictProtected {
		t.Fatalf("precondition: %s", before.Verdict)
	}

	time.Sleep(20 * time.Millisecond)
	db, err := sql.Open("sqlite", w.lockDB)
	if err != nil {
		t.Fatal(err)
	}
	// An unsigned append, as a writer without the signing key would leave.
	if _, err := db.Exec(`INSERT INTO events (timestamp, event_type, category, detail, blocked, session_id) VALUES (?, 'network_blocked', 'network', 'evil.example:443', 1, ?)`,
		time.Now().UTC().Format(time.RFC3339), lockSessA); err != nil {
		t.Fatal(err)
	}
	db.Close()

	if _, ok := pollLock(w.lockDB, last, w.b); !ok {
		t.Fatal("poll failed")
	}
	select {
	case ev := <-c:
		if ev.Source != sourceLock || ev.Tool != "network: evil.example:443" || ev.Decision != "block" {
			t.Fatalf("appended row: %+v", ev)
		}
	default:
		t.Fatal("append was not streamed (the connection must not be immutable)")
	}
	// New rows landed, so the session is re-verified, and the unsigned append
	// can no longer read PROTECTED.
	if after := w.badge(t, lockSessA); after.Verdict == sessionverify.VerdictProtected {
		t.Fatal("badge stayed PROTECTED after an unsigned row landed")
	}
}

func TestDemoShowsLockRowsAndNeverAGreenBadge(t *testing.T) {
	b := newBroker()
	b.demo = true
	rec := httptest.NewRecorder()
	b.handleSessions(rec, httptest.NewRequest(http.MethodGet, "/sessions", nil))
	var out []sessionverify.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out) != 1 || out[0].Verdict != sessionverify.VerdictUnsigned {
		t.Fatalf("demo badge = %v (%v), want one UNSIGNED", out, err)
	}
	for _, s := range lockShots {
		le := toLockEvent("2026-10-12T00:00:00Z", s.eventType, s.detail, strings.HasSuffix(s.eventType, "_blocked"), demoSessionID)
		if le.Source != sourceLock || (le.Decision == "block") != strings.HasSuffix(s.eventType, "_blocked") {
			t.Fatalf("demo shot %s mapped wrong: %+v", s.eventType, le)
		}
	}
}

func TestNoLockDBLeavesBadgesEmpty(t *testing.T) {
	b := newBroker()
	if got := b.sessionBadges(); len(got) != 0 {
		t.Fatalf("badges without --lock-db: %v", got)
	}
	if got := loadLockEvents(""); got != nil {
		t.Fatalf("loadLockEvents(\"\") = %v", got)
	}
}

func TestDemoStreamEmitsLockRows(t *testing.T) {
	b := newBroker()
	c := make(chan event, 64)
	b.register(c)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go demo(ctx, b)
	for {
		select {
		case ev := <-c:
			if ev.Source == sourceLock {
				if ev.Session != demoSessionID || ev.VerifyState != "unknown" {
					t.Fatalf("demo lock row: %+v", ev)
				}
				return
			}
		case <-ctx.Done():
			t.Fatal("demo never emitted a LOCK row")
		}
	}
}

func TestGuardLineCannotClaimLockSource(t *testing.T) {
	evs := loadEventsFromBytes([]byte(`{"ts":"2026-10-12T00:00:00Z","agent":"a","tool":"t","decision":"deny","source":"LOCK"}` + "\n"))
	if len(evs) != 1 || evs[0].Source != sourceGuard {
		t.Fatalf("guard line kept a forged source: %+v", evs)
	}
}

func TestLockLifecycleStatusRowsStayOffTheWall(t *testing.T) {
	w := newLockWall(t)
	before := len(loadLockEvents(w.lockDB))
	db, err := sql.Open("sqlite", w.lockDB)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, d := range []string{"proxy=127.0.0.1:9 domains=3", "netns tproxy egress fence active domains=3"} {
		if _, err := db.Exec(`INSERT INTO events (timestamp, event_type, category, detail, blocked, session_id) VALUES ('2026-10-12T00:00:00Z', 'network_passed', 'network', ?, 0, ?)`, d, lockSessA); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO events (timestamp, event_type, category, detail, blocked, session_id) VALUES ('2026-10-12T00:00:01Z', 'network_passed', 'network', 'method=CONNECT host=api.github.com:443 rule=allow', 0, ?)`, lockSessA); err != nil {
		t.Fatal(err)
	}
	if got := len(loadLockEvents(w.lockDB)); got != before+1 {
		t.Fatalf("lock events = %d, want %d (status rows excluded, a real egress decision kept)", got, before+1)
	}
}

// A real NockLock row (testdata is a genuine events.db) carries the timestamp
// NockLock actually writes: UTC RFC3339 with nine fractional digits and a Z.
// The wall must order, filter and show it by that time, not drop it to zero.
func TestRealNockLockTimestampParses(t *testing.T) {
	w := newLockWall(t)
	rows := loadLockEvents(w.lockDB)
	if len(rows) != 1 {
		t.Fatalf("lock rows = %d, want 1", len(rows))
	}
	const want = "2026-09-25T12:00:02.000000000Z"
	if rows[0].Ts != want {
		t.Fatalf("ts = %q, want the NockLock-written %q", rows[0].Ts, want)
	}
	if _, err := time.Parse(time.RFC3339, rows[0].Ts); err != nil {
		t.Fatalf("NockLock timestamp does not parse as RFC3339: %v", err)
	}
	guard := []event{{Ts: "2026-09-25T11:00:00Z"}, {Ts: "2026-09-25T13:00:00Z"}}
	m := mergeByTime(guard, rows)
	if len(m) != 3 || m[1].Source != sourceLock {
		t.Fatalf("lock row not ordered between the guard rows by its own timestamp: %+v", m)
	}
	since := time.Date(2026, 9, 25, 11, 30, 0, 0, time.UTC)
	until := time.Date(2026, 9, 25, 12, 30, 0, 0, time.UTC)
	if got := filterEvents(m, "", "", "", &since, &until); len(got) != 1 || got[0].Source != sourceLock {
		t.Fatalf("time-window filter lost the real Lock row: %+v", got)
	}
}

func lockExportJSON(t *testing.T, w lockWall) (*httptest.ResponseRecorder, []event) {
	t.Helper()
	rec := httptest.NewRecorder()
	w.b.handleExport(rec, httptest.NewRequest(http.MethodGet, "/export?format=json", nil))
	var out []event
	if rec.Code != http.StatusOK {
		t.Fatalf("export status %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return rec, out
}

// The export marks a Lock row verified only from the snapshot it verified, and
// says so when the Lock side is unusable.
func TestExportLockRowsFromVerifiedSnapshot(t *testing.T) {
	w := newLockWall(t)
	rec, out := lockExportJSON(t, w)
	if rec.Header().Get("X-NockGuard-Lock-Verification") != "ok" {
		t.Fatalf("lock header = %q", rec.Header().Get("X-NockGuard-Lock-Verification"))
	}
	var lock int
	for _, ev := range out {
		if ev.Source == sourceLock {
			lock++
			if ev.Verification != "verified" {
				t.Fatalf("clean Lock row = %q, want verified", ev.Verification)
			}
		}
	}
	if lock != 1 {
		t.Fatalf("lock rows in export = %d, want 1", lock)
	}

	// Negative control: edit a Lock row; the export row must read failed.
	db, err := sql.Open("sqlite", w.lockDB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE events SET detail = '/etc/shadoX' WHERE id = 3`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	_, out = lockExportJSON(t, w)
	for _, ev := range out {
		if ev.Source == sourceLock && ev.Verification != "failed" {
			t.Fatalf("tampered Lock row = %q, want failed", ev.Verification)
		}
	}

	// Unreadable Lock DB: no Lock rows, none marked verified, and it says so.
	if err := os.Remove(w.lockDB); err != nil {
		t.Fatal(err)
	}
	rec, out = lockExportJSON(t, w)
	if rec.Header().Get("X-NockGuard-Lock-Verification") != "unavailable" {
		t.Fatalf("lock header = %q, want unavailable", rec.Header().Get("X-NockGuard-Lock-Verification"))
	}
	for _, ev := range out {
		if ev.Source == sourceLock {
			t.Fatalf("lock row exported without a snapshot: %+v", ev)
		}
	}
}

// Lock rows must never push Guard rows out of the export.
func TestExportLockRowsDoNotDisplaceGuardRows(t *testing.T) {
	guard := make([]event, maxWindow)
	for i := range guard {
		guard[i] = event{Ts: "2026-09-25T10:00:00Z", Source: sourceGuard}
	}
	lock := []event{{Ts: "2026-09-25T12:00:02.000000000Z", Source: sourceLock}}
	m := mergeByTime(guard, lock)
	if len(m) != maxWindow+1 {
		t.Fatalf("merged %d rows, want %d: a Lock row displaced a Guard row", len(m), maxWindow+1)
	}
}

func TestLockDBSymlinkRefused(t *testing.T) {
	w := newLockWall(t)
	link := filepath.Join(t.TempDir(), "link.db")
	if err := os.Symlink(w.lockDB, link); err != nil {
		t.Skip(err)
	}
	if _, err := snapshotLock(link); err == nil {
		t.Fatal("snapshotLock followed a symlink")
	}
	if err := sessionverify.RequireRegularFile(link); err == nil {
		t.Fatal("RequireRegularFile accepted a symlink")
	}
	if res := sessionverify.Verify(lockSessA, link, w.b.lockPub, w.b.auditPath, w.guardPub); res.Lock.Verdict == sessionverify.ChainVerdictIntact || !strings.Contains(res.Lock.Reason, "symlink") {
		t.Fatalf("verify followed a symlinked lock db: %+v", res.Lock)
	}
}

// A failed poll must not consume the change: the next tick retries.
func TestFailedPollKeepsCursor(t *testing.T) {
	w := newLockWall(t)
	last, ok := pollLock(w.lockDB, -1, w.b)
	if !ok {
		t.Fatal("first poll failed")
	}
	if got, ok := pollLock(w.lockDB+".missing", last, w.b); ok || got != last {
		t.Fatalf("failed poll = (%d, %v), want cursor kept and ok=false", got, ok)
	}
}

// A row that cannot be scanned is skipped; the valid rows after it still load.
func TestMalformedLockRowDoesNotHideLaterRows(t *testing.T) {
	w := newLockWall(t)
	db, err := sql.Open("sqlite", w.lockDB)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, blocked := range []any{"not-a-number", 1} {
		if _, err := db.Exec(`INSERT INTO events (timestamp, event_type, category, detail, blocked, session_id) VALUES ('2026-10-12T00:00:00Z', 'network_blocked', 'network', 'after.example:443', ?, ?)`, blocked, lockSessA); err != nil {
			t.Fatal(err)
		}
	}
	evs := loadLockEvents(w.lockDB)
	if last := evs[len(evs)-1]; !strings.Contains(last.Tool, "after.example") {
		t.Fatalf("valid row after the malformed one was lost: %+v", last)
	}
}

// An unsigned export keeps every Guard row even when Lock rows fill the
// combined display window.
func TestUnsignedExportKeepsGuardRowsUnderLockFlood(t *testing.T) {
	w := newLockWall(t)
	w.b.verifier = nil
	db, err := sql.Open("sqlite", w.lockDB)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for i := 0; i < maxWindow+50; i++ {
		if _, err := db.Exec(`INSERT INTO events (timestamp, event_type, category, detail, blocked, session_id) VALUES ('2099-01-01T00:00:00Z', 'network_blocked', 'network', 'flood.example:443', 1, ?)`, lockSessA); err != nil {
			t.Fatal(err)
		}
	}
	rec, out := lockExportJSON(t, w)
	var guard int
	for _, ev := range out {
		if ev.Source == sourceGuard {
			guard++
		}
		if ev.Verification != "unsigned" {
			t.Fatalf("row verification = %q, want unsigned", ev.Verification)
		}
	}
	if guard != 2 {
		t.Fatalf("exported %d Guard rows, want 2", guard)
	}
	if h := rec.Header().Get("X-NockGuard-Lock-Verification"); h != "unsigned" {
		t.Fatalf("lock header = %q, want unsigned", h)
	}
}
