package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/nocktechnologies/nockguard/internal/forward"
	"github.com/nocktechnologies/nockguard/internal/sessionverify"
	_ "modernc.org/sqlite" // registers the "sqlite" driver (already linked via nocklock/pkg/receipt)
)

// Source labels on a wall event: which enforcement layer recorded it.
const (
	sourceGuard = "GUARD"
	sourceLock  = "LOCK"
)

// lockEventTypes are the NockLock fence events the wall shows: file, network
// and secret, blocked and passed. Lifecycle rows (session_start, proxy_start,
// config_loaded, …) are not enforcement decisions and stay off the wall.
var lockEventTypes = []string{"file_blocked", "file_passed", "network_blocked", "network_passed", "secret_blocked", "secret_passed"}

// decisionUnparseable marks a fence row that could not be read. It is shown in
// the stream (never silently dropped) and counts against its session's badge.
const decisionUnparseable = forward.DecisionUnparseable

// lockSelect reads the decision columns only, by id; the caller adds the id
// range. The chain columns (prev_hash, entry_hash, entry_sig) are the verifier's
// business, never the stream's. SQL never filters on event_type or detail: Go
// classifies every row (see isLifecycleRow), so a row SQL cannot compare (NULL,
// BLOB) is never silently dropped.
const lockSelect = `SELECT id, timestamp, event_type, detail, blocked, session_id FROM events`

// isLifecycleRow reports a text event_type that is not a fence decision. That
// includes the two session-start network_passed records that are fence status
// ("proxy=… domains=N" and "netns tproxy egress fence active …").
func isLifecycleRow(eventType, detail string) bool {
	if !slices.Contains(lockEventTypes, eventType) {
		return true
	}
	return eventType == "network_passed" && (strings.HasPrefix(detail, "proxy=") || strings.HasPrefix(detail, "netns tproxy egress fence"))
}

// openLockDB opens the NockLock log read-only. mode=ro plus query_only means
// the wall can never write it; immutable is deliberately NOT set so SQLite
// keeps seeing rows nocklock appends while the wall runs.
func openLockDB(path string) (*sql.DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: abs, RawQuery: "mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(3000)"}
	return sql.Open("sqlite", u.String())
}

// toLockEvent maps a fence row to a wall event: the DECISION only. detail is
// what the fence recorded about the target (a path, a host, a secret NAME) —
// the same kind of field as a Guard tool name; no request or file payload and
// no secret value is stored in the log, so none can reach the wall.
func toLockEvent(ts, eventType, detail string, blocked bool, session string) event {
	kind, _, _ := strings.Cut(eventType, "_")
	decision := "allow"
	if blocked || strings.HasSuffix(eventType, "_blocked") {
		decision = "block"
	}
	ev := classify(event{
		Ts:       ts,
		Agent:    "nocklock",
		Tool:     kind + ": " + detail,
		Decision: decision,
		// The target rides in Reason too so forward.Severity (which reads only
		// decision+reason) ranks a blocked /etc/shadow or ~/.ssh read as critical.
		Reason:      eventType + " " + detail,
		Session:     session,
		VerifyState: "unknown", // per-row badges are Guard-chain only; Lock proof is the session badge
	})
	ev.Source = sourceLock
	return ev
}

// lockText reads a text column; ok is false for NULL or any other type.
func lockText(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case []byte:
		return string(t), true
	}
	return "", false
}

// unparseableLockEvent stands in for a fence row that cannot be read. It names
// the row id and a fixed label only, never any content of the bad row.
func unparseableLockEvent(id any, ts, session string) event {
	n, ok := id.(int64)
	tool := "row #?"
	if ok {
		tool = fmt.Sprintf("row #%d", n)
	}
	ev := classify(event{
		Ts:          ts,
		Agent:       "nocklock",
		Tool:        tool,
		Decision:    decisionUnparseable,
		Reason:      "UNPARSEABLE fence row: it cannot be read, so its session cannot be verified",
		Session:     session,
		VerifyState: "unknown",
	})
	ev.Source = sourceLock
	return ev
}

// lockRowsErr reports the iteration error after the last row; a test seam.
var lockRowsErr = func(r *sql.Rows) error { return r.Err() }

// scanLockRows classifies every row into a wall event. A row that cannot be read
// (NULL or non-text event_type, bad column) becomes an UNPARSEABLE event and the
// scan continues; lifecycle rows are skipped. It stops after limit events when
// limit > 0. The error is the iteration error, if any: the caller must then
// treat the batch as incomplete.
func scanLockRows(rows *sql.Rows, limit int) ([]event, error) {
	defer rows.Close()
	var out []event
	for rows.Next() {
		if limit > 0 && len(out) >= limit {
			break
		}
		var id, ts, eventType, detail, blocked, sess any
		if err := rows.Scan(&id, &ts, &eventType, &detail, &blocked, &sess); err != nil {
			out = append(out, unparseableLockEvent(nil, "", ""))
			continue
		}
		t, ok1 := lockText(ts)
		et, ok2 := eventType.(string) // a BLOB event_type is not text either
		d, ok3 := lockText(detail)
		s, ok4 := lockText(sess)
		bl, ok5 := blocked.(int64)
		if !(ok1 && ok2 && ok3 && ok4 && ok5) {
			out = append(out, unparseableLockEvent(id, t, s))
			continue
		}
		if isLifecycleRow(et, d) {
			continue
		}
		out = append(out, toLockEvent(t, et, d, bl != 0, s))
	}
	return out, lockRowsErr(rows)
}

// loadLockEvents returns up to the most recent maxWindow fence events, oldest
// first. An unreadable or absent DB yields nil: the wall keeps running and the
// session badge reports UNVERIFIABLE.
func loadLockEvents(path string) []event {
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	db, err := openLockDB(path)
	if err != nil {
		return nil
	}
	defer db.Close()
	rows, err := db.Query(lockSelect + ` ORDER BY id DESC`)
	if err != nil {
		log.Printf("lock db: %v", err)
		return nil
	}
	evs, err := scanLockRows(rows, maxWindow)
	if err != nil {
		log.Printf("lock db: %v", err)
	}
	slices.Reverse(evs) // newest-first → oldest-first
	return evs
}

// tailLock polls the NockLock log for appended fence rows and emits them. Like
// tail, it follows new rows only; existing history is replayed per client.
func tailLock(ctx context.Context, path string, b *broker) {
	var last int64 = -1
	var sig string
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
		// An idle log costs two stats, not a DB open (appends touch the WAL).
		// This only gates the row stream. It is not tamper detection (badges
		// re-verify on a timer), and a failed poll leaves sig alone so the next
		// tick retries instead of losing the change.
		if cur := fileSig(path) + walSig(path+"-wal"); cur != sig {
			var ok bool
			if last, ok = pollLock(path, last, b); ok {
				sig = cur
			}
		}
	}
}

// pollLock emits fence rows with id > last and returns the new high-water id.
// last < 0 means "first look": adopt the current max id without emitting. A
// shrunken max id (the log was replaced) resets the cursor. ok is false when
// the poll failed; the cursor is unchanged and nothing was emitted.
func pollLock(path string, last int64, b *broker) (next int64, ok bool) {
	if _, err := os.Stat(path); err != nil {
		return last, false
	}
	db, err := openLockDB(path)
	if err != nil {
		return last, false
	}
	defer db.Close()
	// One read transaction, so the MAX(id) cursor and the rows fetched below
	// are the same snapshot: a row appended in between is neither lost nor
	// emitted twice.
	tx, err := db.Begin()
	if err != nil {
		return last, false
	}
	defer tx.Rollback()
	var max sql.NullInt64
	if err := tx.QueryRow(`SELECT MAX(id) FROM events`).Scan(&max); err != nil {
		return last, false
	}
	switch {
	case last < 0 || max.Int64 < last:
		return max.Int64, true
	case max.Int64 == last:
		return last, true
	}
	rows, err := tx.Query(lockSelect+` WHERE id > ? ORDER BY id ASC`, last)
	if err != nil {
		return last, false
	}
	// A batch is all or nothing: a row that cannot be read becomes an UNPARSEABLE
	// event, but an iteration error leaves the cursor where it was and emits
	// nothing, so the next tick retries the whole batch.
	evs, err := scanLockRows(rows, 0)
	if err != nil {
		log.Printf("lock db: %v", err)
		return last, false
	}
	for _, ev := range evs {
		b.emit(ev)
	}
	return max.Int64, true
}

// maxLockVerifyRows bounds the Lock log the wall will copy and verify. A
// verification walks the whole hash chain, so the cost grows with the log; above
// this many events the session badges read UNVERIFIABLE (too large) instead of
// the wall freezing on a copy. See docs/verifying-the-trail.md.
const maxLockVerifyRows = 100_000

// tooLargeError reports a Lock log above maxLockVerifyRows.
type tooLargeError struct{ rows int }

func (e *tooLargeError) Error() string {
	return fmt.Sprintf("lock log too large to verify (%d events, limit %d)", e.rows, maxLockVerifyRows)
}

// lockSnapshot is a private, consistent copy of the Lock DB. SQLite's VACUUM
// INTO copies the database in one read transaction, so the verifier and the
// row reader both see exactly these bytes, whatever the live writer does next.
// The copy is the only file the verifier and the rows ever touch.
type lockSnapshot struct {
	dir  string
	Path string
	live string // the live path, shown in place of the copy's
}

// snapshotLock copies the log unless it holds more than maxLockVerifyRows
// events (*tooLargeError, nothing copied).
func snapshotLock(path string) (*lockSnapshot, error) {
	if err := sessionverify.RequireRegularFile(path); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	// mode=ro keeps the live file unwritable; query_only is omitted only
	// because it would also forbid VACUUM INTO, which writes the new copy.
	u := url.URL{Scheme: "file", Path: abs, RawQuery: "mode=ro&_pragma=busy_timeout(3000)"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n); err != nil {
		return nil, fmt.Errorf("count lock events: %w", err)
	}
	if n > maxLockVerifyRows {
		return nil, &tooLargeError{rows: n}
	}
	dir, err := os.MkdirTemp("", "nockwall-lock-")
	if err != nil {
		return nil, err
	}
	s := &lockSnapshot{dir: dir, Path: filepath.Join(dir, "events.db"), live: path}
	if _, err := db.Exec(`VACUUM INTO ?`, s.Path); err != nil {
		s.Close()
		return nil, fmt.Errorf("snapshot lock db: %s", s.scrub(err.Error()))
	}
	return s, nil
}

// scrub replaces the temporary copy's path in a message with the live path, so
// no reason string ever names a file the operator cannot find.
func (s *lockSnapshot) scrub(msg string) string {
	return strings.ReplaceAll(strings.ReplaceAll(msg, s.Path, s.live), s.dir, filepath.Dir(s.live))
}

// Close removes the snapshot directory this process created.
func (s *lockSnapshot) Close() { _ = os.RemoveAll(s.dir) }
