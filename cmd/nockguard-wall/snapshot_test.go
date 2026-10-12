package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/sessionverify"
)

func (w lockWall) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	db, err := sql.Open("sqlite", w.lockDB)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}

// countTrailOpens counts opens of the Guard trail itself (not its .hwm).
func (w lockWall) countTrailOpens(t *testing.T) *int {
	t.Helper()
	orig := sessionverify.GuardSnapshotOpen
	t.Cleanup(func() { sessionverify.GuardSnapshotOpen = orig })
	n := 0
	sessionverify.GuardSnapshotOpen = func(name string) (*os.File, error) {
		if name == w.b.auditPath {
			n++
		}
		return orig(name)
	}
	return &n
}

// One refresh reads the Guard trail once, however many views it feeds.
func TestRefreshReadsGuardTrailOnce(t *testing.T) {
	w := newLockWall(t)
	opens := w.countTrailOpens(t)
	v := w.b.currentView()
	if *opens != 1 {
		t.Fatalf("trail opened %d times for one refresh, want 1", *opens)
	}
	if len(v.guardEvs) != 2 || len(v.lock.badges) == 0 || v.lock.badges[0].Verdict != sessionverify.VerdictProtected {
		t.Fatalf("view = %d guard rows, badges %+v", len(v.guardEvs), v.lock.badges)
	}
	// Pulse, badges and the cached window reuse that snapshot.
	w.b.windowEvents()
	w.b.sessionBadges()
	if *opens != 1 {
		t.Fatalf("views re-read the trail: %d opens, want 1", *opens)
	}
	// A reconnecting browser gets a fresh snapshot, still read once.
	w.b.replayHistory(&strings.Builder{})
	if *opens != 2 {
		t.Fatalf("replay opened the trail %d times in total, want 2 (one cached build, one fresh)", *opens)
	}
}

// A reconnecting browser sees rows recorded after the cached view was built.
func TestReplaySeesRowsNewerThanCachedView(t *testing.T) {
	w := newLockWall(t)
	w.b.currentView()
	w.exec(t, `INSERT INTO events (timestamp, event_type, category, detail, blocked, session_id) VALUES (?, 'file_blocked', 'file', '/tmp/late', 1, ?)`,
		time.Now().UTC().Format(time.RFC3339), lockSessA)
	if strings.Contains(joinEvents(w.b.currentView().lock.events), "/tmp/late") {
		t.Fatal("precondition: the cached view should predate the row")
	}
	var sb strings.Builder
	w.b.replayHistory(&sb)
	if !strings.Contains(sb.String(), "/tmp/late") {
		t.Fatal("replay served a stale view and lost a row")
	}
}

func joinEvents(evs []event) string {
	var sb strings.Builder
	for _, e := range evs {
		sb.WriteString(e.Tool + "\n")
	}
	return sb.String()
}

// A fence row with a NULL detail is surfaced as UNPARSEABLE, not filtered out.
func TestNullDetailNetworkRowIsUnparseableNotDropped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE events (id INTEGER PRIMARY KEY, timestamp TEXT, event_type TEXT, detail TEXT, blocked INTEGER, session_id TEXT)`,
		`INSERT INTO events VALUES (1, '2026-10-12T00:00:00Z', 'network_passed', NULL, 0, 's')`,
		`INSERT INTO events VALUES (2, '2026-10-12T00:00:01Z', 'network_passed', 'proxy=x domains=1', 0, 's')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	evs := loadLockEvents(path)
	// The NULL row surfaces; the status row (row 2) stays off the wall.
	if len(evs) != 1 || evs[0].Decision != decisionUnparseable {
		t.Fatalf("rows = %+v, want exactly one UNPARSEABLE row", evs)
	}
}

// A Guard trail above the snapshot cap still shows its rows, never as verified.
func TestOverCapGuardTrailShowsRowsUnverified(t *testing.T) {
	w := newLockWall(t)
	w.b.exportTrailLimit = 16
	v := w.b.freshView()
	if len(v.guardEvs) != 2 {
		t.Fatalf("over-cap trail shows %d guard rows, want 2", len(v.guardEvs))
	}
	if v.rep.ChainIntact != nil || v.rep.Status != statusUnavailable {
		t.Fatalf("over-cap trail report = %+v, want unavailable", v.rep)
	}
	for _, ev := range v.guardEvs {
		if got := exportRowVerification(v.rep, v.lock.verdicts(), ev); got != "unsigned" {
			t.Fatalf("over-cap row = %q, want unsigned", got)
		}
	}
}

// The refresh cadence: nothing within sessionReverify, nothing later while the
// heads are unchanged, a refresh once a head moves, and a forced one at 60 s.
func TestRefreshCadence(t *testing.T) {
	w := newLockWall(t)
	opens := w.countTrailOpens(t)
	w.b.currentView()
	age := func(d time.Duration) { w.b.view.at = time.Now().Add(-d) }

	age(sessionReverify / 2)
	w.b.currentView()
	if *opens != 1 {
		t.Fatalf("rebuilt inside the minimum interval: %d opens", *opens)
	}
	age(10 * time.Second) // past the minimum, heads unchanged
	w.b.currentView()
	if *opens != 1 {
		t.Fatalf("rebuilt with unchanged heads at 10 s: %d opens", *opens)
	}
	w.exec(t, `INSERT INTO events (timestamp, event_type, category, detail, blocked, session_id) VALUES (?, 'file_passed', 'file', '/tmp/x', 0, ?)`,
		time.Now().UTC().Format(time.RFC3339), lockSessA)
	age(10 * time.Second) // head moved
	w.b.currentView()
	if *opens != 2 {
		t.Fatalf("no rebuild after the head moved: %d opens", *opens)
	}
	age(2 * forcedReverify) // nothing moved, but the forced interval lapsed
	w.b.currentView()
	if *opens != 3 {
		t.Fatalf("no forced rebuild after %s: %d opens", forcedReverify, *opens)
	}
}

// The Guard side of a badge is judged on the bytes of the snapshot, never on a
// re-read of the live trail.
func TestGuardBadgeUsesSnapshotBytes(t *testing.T) {
	w := newLockWall(t)
	trail, err := os.ReadFile(w.b.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	hwm, err := os.ReadFile(w.b.auditPath + ".hwm")
	if err != nil {
		t.Fatal(err)
	}
	bad := []byte(strings.Replace(string(trail), `"Bash"`, `"Basx"`, 1))
	if string(bad) == string(trail) {
		t.Fatal("fixture edit did not apply")
	}
	// Live trail is clean; the snapshot bytes are tampered: the badge must say so.
	v := w.b.buildView(guardRead{trail: bad, hwm: hwm})
	if got := v.lock.badges[0]; got.Guard.Verdict != sessionverify.VerdictTampered {
		t.Fatalf("guard verdict on tampered snapshot bytes = %s, want TAMPERED", got.Guard.Verdict)
	}
	// Negative control: the same live trail, clean bytes, reads PROTECTED.
	v = w.b.buildView(guardRead{trail: trail, hwm: hwm})
	if got := v.lock.badges[0]; got.Verdict != sessionverify.VerdictProtected {
		t.Fatalf("clean snapshot = %s, want PROTECTED", got.Verdict)
	}
}

// With no key configured the export still carries Guard AND Lock rows, from one
// snapshot, and marks none of them verified.
func TestUnsignedExportKeepsGuardAndLockRows(t *testing.T) {
	w := newLockWall(t)
	w.b.verifier = &verifier{mode: modeNone}
	rec := httptest.NewRecorder()
	w.b.handleExport(rec, httptest.NewRequest(http.MethodGet, "/export?format=json", nil))
	var out []event
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	var guard, lock int
	for _, ev := range out {
		if ev.Verification != "unsigned" {
			t.Fatalf("row %+v marked %q with no key configured", ev, ev.Verification)
		}
		if ev.Source == sourceLock {
			lock++
		} else {
			guard++
		}
	}
	if guard != 2 || lock != 1 {
		t.Fatalf("export has %d guard / %d lock rows, want 2 / 1", guard, lock)
	}
	if rec.Header().Get("X-NockGuard-Lock-Verification") == "" {
		t.Fatal("unsigned export dropped the Lock verification header")
	}
}

// One unreadable row is shown as UNPARSEABLE and the rest of the batch is
// still emitted; the session badge cannot be green.
func TestUnparseableRowDoesNotSkipTheBatch(t *testing.T) {
	w := newLockWall(t)
	c := make(chan event, 8)
	w.b.register(c)
	last, _ := pollLock(w.lockDB, -1, w.b)
	ts := time.Now().UTC().Format(time.RFC3339)
	ins := `INSERT INTO events (timestamp, event_type, category, detail, blocked, session_id) VALUES (?, ?, 'x', ?, ?, ?)`
	w.exec(t, ins, ts, "file_passed", "/tmp/one", 0, lockSessA)
	w.exec(t, ins, ts, "file_blocked", "SECRET-DETAIL", "not-a-number", lockSessA) // blocked is not an integer
	w.exec(t, ins, ts, "network_blocked", "two.example:443", 1, lockSessA)
	if _, ok := pollLock(w.lockDB, last, w.b); !ok {
		t.Fatal("poll failed")
	}
	var got []event
	for len(c) > 0 {
		got = append(got, <-c)
	}
	if len(got) != 3 {
		t.Fatalf("emitted %d rows, want 3 (the bad row must not skip its neighbours): %+v", len(got), got)
	}
	if got[0].Tool != "file: /tmp/one" || got[2].Tool != "network: two.example:443" {
		t.Fatalf("neighbours of the bad row: %+v / %+v", got[0], got[2])
	}
	bad := got[1]
	if bad.Decision != decisionUnparseable || bad.Source != sourceLock || bad.Session != lockSessA {
		t.Fatalf("bad row = %+v, want an UNPARSEABLE LOCK row of %s", bad, lockSessA)
	}
	if b, _ := json.Marshal(bad); strings.Contains(string(b), "SECRET-DETAIL") {
		t.Fatalf("unparseable row leaks the bad row's content: %s", b)
	}

	// The badge counts it: never PROTECTED.
	if b := w.badge(t, lockSessA); b.Verdict == sessionverify.VerdictProtected {
		t.Fatalf("badge = %s with an unparseable row in the session", b.Verdict)
	}
	// And a snapshot-backed replay shows it too.
	var sb strings.Builder
	w.b.replayHistory(&sb)
	if !strings.Contains(sb.String(), decisionUnparseable) {
		t.Fatal("replay hides the unparseable row")
	}
}

// Negative control: a clean batch shows no UNPARSEABLE row.
func TestCleanBatchHasNoUnparseableRow(t *testing.T) {
	w := newLockWall(t)
	for _, ev := range w.b.currentView().lock.events {
		if ev.Decision == decisionUnparseable {
			t.Fatalf("clean log shows %+v", ev)
		}
	}
}

// Above the documented row limit nothing is copied or verified: every badge is
// UNVERIFIABLE and says "too large", and the rows are not marked verified.
func TestOverRowLimitIsUnverifiableNotFrozen(t *testing.T) {
	w := newLockWall(t)
	w.exec(t, `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < ?)
		INSERT INTO events (timestamp, event_type, category, detail, blocked, session_id)
		SELECT '2026-10-12T00:00:00Z', 'session_end', 'x', 'fill', 0, 'session-a' FROM c`, maxLockVerifyRows)
	v := w.b.currentView()
	if len(v.lock.badges) == 0 {
		t.Fatal("no badges")
	}
	for _, b := range v.lock.badges {
		if b.Verdict != sessionverify.VerdictUnverifiable || !strings.Contains(b.Lock.Reason, "too large") {
			t.Fatalf("badge over the limit = %s %q", b.Verdict, b.Lock.Reason)
		}
	}
	if len(v.lock.events) == 0 {
		t.Fatal("rows vanished instead of being shown unverified")
	}
	if got := exportRowVerification(v.rep, v.lock.verdicts(), event{Source: sourceLock, Session: lockSessA}); got != "unsigned" {
		t.Fatalf("export row over the limit = %q, want unsigned", got)
	}
}

// Reason strings name the live log, never the temporary copy.
func TestReasonsNeverShowSnapshotPath(t *testing.T) {
	w := newLockWall(t)
	w.exec(t, `UPDATE events SET detail = '/etc/shadoX' WHERE id = 3`)
	b := w.badge(t, lockSessA)
	out, _ := json.Marshal(b)
	if b.Lock.Verdict != sessionverify.VerdictTampered || b.Lock.Reason == "" {
		t.Fatalf("precondition: want a TAMPERED lock reason, got %+v", b.Lock)
	}
	if strings.Contains(string(out), "nockwall-lock-") {
		t.Fatalf("badge shows the snapshot path: %s", out)
	}
	if b.Lock.Path != w.lockDB {
		t.Fatalf("lock path = %q, want the live %q", b.Lock.Path, w.lockDB)
	}

	// The scrub itself: the copy's path and directory map to the live ones.
	snap, err := snapshotLock(w.lockDB)
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	if got := snap.scrub("open " + snap.Path + " in " + snap.dir); got != "open "+w.lockDB+" in "+filepath.Dir(w.lockDB) {
		t.Fatalf("scrub = %q", got)
	}
}
