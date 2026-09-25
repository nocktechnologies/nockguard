package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/pkg/receipt" // also registers the "sqlite" driver used to mutate fixtures

	"github.com/nocktechnologies/nockguard/internal/audit"
)

// The NockLock fixture (testdata/nocklock-signed.db + .pub) is a byte copy of
// nocklock's pkg/receipt/testdata at 771c18b2, written by nocklock's real
// signing Logger. Its chain has 5 rows: session-a = ids 1, 3, 4; session-b =
// ids 2, 5; a signed chain_head anchors all 5. nockguard cannot import
// nocklock/internal/logging to mint Lock rows itself, so every Lock case below
// starts from this genuine signed chain and mutates a copy of it the way a
// file-level attacker would.
const (
	sessA   = "session-a"
	sessB   = "session-b"
	lockEnv = "TEST_NOCKLOCK_PUB"
	guardEv = "TEST_NOCKGUARD_PUB"
)

type sessionFixture struct {
	dir       string
	lockDB    string
	guardPath string
	guardPriv ed25519.PrivateKey
	guardPub  ed25519.PublicKey
}

// newSessionFixture copies the signed Lock DB into a temp dir and records a
// signed Guard trail through the real audit.Auditor: two session-a lines, one
// session-b line, and a trailing session-a line.
func newSessionFixture(t *testing.T) sessionFixture {
	t.Helper()
	dir := t.TempDir()
	db, err := os.ReadFile(filepath.Join("testdata", "nocklock-signed.db"))
	if err != nil {
		t.Fatalf("read lock fixture: %v", err)
	}
	lockDB := filepath.Join(dir, "events.db")
	if err := os.WriteFile(lockDB, db, 0o600); err != nil {
		t.Fatal(err)
	}
	pubHex, err := os.ReadFile(filepath.Join("testdata", "nocklock-signed.pub"))
	if err != nil {
		t.Fatalf("read lock pub: %v", err)
	}
	t.Setenv(lockEnv, strings.TrimSpace(string(pubHex)))

	gpub, gpriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(guardEv, hex.EncodeToString(gpub))
	guardPath := filepath.Join(dir, "coder.audit.jsonl")
	a, err := audit.New(guardPath, audit.WithEd25519Key(gpriv))
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	for _, ev := range []audit.Event{
		{Agent: "coder", Tool: "Read", Decision: "allow", SessionID: sessA},
		{Agent: "coder", Tool: "Bash", Decision: "deny", Reason: "policy", SessionID: sessA},
		{Agent: "coder", Tool: "Read", Decision: "allow", SessionID: sessB},
		{Agent: "coder", Tool: "Write", Decision: "allow", SessionID: sessA},
	} {
		if err := a.Record(ev); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	return sessionFixture{dir: dir, lockDB: lockDB, guardPath: guardPath, guardPriv: gpriv, guardPub: gpub}
}

func (f sessionFixture) args(session string, extra ...string) []string {
	a := []string{"verify", "--session", session, "--lock-db", f.lockDB, "--guard-trail", f.guardPath,
		"--lock-pub-env", lockEnv, "--guard-pub-env", guardEv}
	return append(a, extra...)
}

func lockExec(t *testing.T, dbPath, stmt string, args ...any) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	res, err := db.Exec(stmt, args...)
	if err != nil {
		t.Fatalf("lock mutation %q: %v", stmt, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("lock mutation %q affected %d rows, want 1", stmt, n)
	}
}

func lockScalar(t *testing.T, dbPath, q string) string {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var s string
	if err := db.QueryRow(q).Scan(&s); err != nil {
		t.Fatalf("lock query %q: %v", q, err)
	}
	return s
}

// verdictLine returns the value of the final "VERDICT: X" line.
func verdictLine(out string) string {
	v := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "VERDICT: ") {
			v = strings.TrimSpace(strings.TrimPrefix(l, "VERDICT: "))
		}
	}
	return v
}

func requireVerdict(t *testing.T, args []string, wantVerdict string, wantCode int) string {
	t.Helper()
	code, stdout, stderr := runCommandForTest(t, args...)
	got := verdictLine(stdout)
	if got != wantVerdict || code != wantCode {
		t.Fatalf("verdict=%q exit=%d, want %s/%d\nstdout:\n%s\nstderr:\n%s", got, code, wantVerdict, wantCode, stdout, stderr)
	}
	if wantVerdict != "PROTECTED" && strings.Contains(stdout, "VERDICT: PROTECTED") {
		t.Fatalf("output claims PROTECTED on a %s run:\n%s", wantVerdict, stdout)
	}
	return stdout
}

func fp(pub []byte) string {
	s := sha256.Sum256(pub)
	return hex.EncodeToString(s[:])
}

func TestSessionVerify_BothIntactIsProtected(t *testing.T) {
	f := newSessionFixture(t)
	out := requireVerdict(t, f.args(sessA), "PROTECTED", 0)
	lockPub, _ := hex.DecodeString(os.Getenv(lockEnv))
	for _, want := range []string{fp(lockPub), fp(f.guardPub), "--against-remote-anchor", "3 rows", "3 of 4"} {
		if !strings.Contains(out, want) {
			t.Fatalf("PROTECTED output missing %q:\n%s", want, out)
		}
	}
	// --pub-env applies one key to both chains; the Guard trail here was signed
	// by a different key than the Lock chain, so it must not verify.
	code, stdout, _ := runCommandForTest(t, "verify", "--session", sessA, "--lock-db", f.lockDB,
		"--guard-trail", f.guardPath, "--pub-env", lockEnv)
	if code == 0 || verdictLine(stdout) == "PROTECTED" {
		t.Fatalf("--pub-env with the Lock key verified a Guard trail signed by another key: exit=%d\n%s", code, stdout)
	}
}

func TestSessionVerify_MissingGuardChainFails(t *testing.T) {
	f := newSessionFixture(t)
	f.guardPath = filepath.Join(f.dir, "absent.audit.jsonl")
	requireVerdict(t, f.args(sessA), "UNVERIFIABLE", 1)

	// A missing Lock DB fails the same way.
	f = newSessionFixture(t)
	f.lockDB = filepath.Join(f.dir, "absent.db")
	requireVerdict(t, f.args(sessA), "UNVERIFIABLE", 1)
}

func TestSessionVerify_EmptyGuardTrailFails(t *testing.T) {
	f := newSessionFixture(t)
	empty := filepath.Join(f.dir, "empty.audit.jsonl")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	f.guardPath = empty
	out := requireVerdict(t, f.args(sessA), "NO_ROWS", 1)
	if !strings.Contains(out, "NockGuard") || !strings.Contains(out, "NO_ROWS") {
		t.Fatalf("empty Guard trail must be reported per chain as NO_ROWS:\n%s", out)
	}
}

func TestSessionVerify_UnsignedLockFails(t *testing.T) {
	f := newSessionFixture(t)
	lockExec(t, f.lockDB, "UPDATE events SET entry_sig='' WHERE id=3")
	requireVerdict(t, f.args(sessA), "UNSIGNED", 1)
}

func TestSessionVerify_UnknownSessionFails(t *testing.T) {
	f := newSessionFixture(t)
	// Zero rows in both chains.
	requireVerdict(t, f.args("no-such-session"), "NO_ROWS", 1)

	// Rows in the Lock chain only: a Guard trail that never saw the session.
	g := newSessionFixture(t)
	only := filepath.Join(g.dir, "other.audit.jsonl")
	a, err := audit.New(only, audit.WithEd25519Key(g.guardPriv))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Record(audit.Event{Agent: "coder", Tool: "Read", Decision: "allow", SessionID: "unrelated"}); err != nil {
		t.Fatal(err)
	}
	_ = a.Close()
	g.guardPath = only
	requireVerdict(t, g.args(sessA), "NO_ROWS", 1)
}

func TestSessionVerify_TruncationWithoutAnchor(t *testing.T) {
	truncateGuard := func(t *testing.T, path string) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.SplitAfter(strings.TrimRight(string(data), "\n"), "\n")
		if len(lines) < 2 {
			t.Fatalf("guard trail too short to truncate: %d lines", len(lines))
		}
		kept := strings.Join(lines[:len(lines)-1], "")
		if err := os.WriteFile(path, []byte(kept), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Lock tail truncated, head untouched: head anchors 5 rows, log holds 4.
	f := newSessionFixture(t)
	lockExec(t, f.lockDB, "DELETE FROM events WHERE id=5")
	requireVerdict(t, f.args(sessA), "TAMPERED", 2)

	// Guard tail truncated, .hwm untouched: sidecar records 4, trail holds 3.
	f = newSessionFixture(t)
	truncateGuard(t, f.guardPath)
	out := requireVerdict(t, f.args(sessA), "TAMPERED", 2)
	if !strings.Contains(out, "truncated") {
		t.Fatalf("Guard truncation must be reported by the .hwm check:\n%s", out)
	}

	// Both chains truncated in step.
	f = newSessionFixture(t)
	lockExec(t, f.lockDB, "DELETE FROM events WHERE id=5")
	truncateGuard(t, f.guardPath)
	requireVerdict(t, f.args(sessA), "TAMPERED", 2)

	// Guard truncated AND its .hwm deleted: still not clean.
	f = newSessionFixture(t)
	truncateGuard(t, f.guardPath)
	if err := os.Remove(f.guardPath + ".hwm"); err != nil {
		t.Fatal(err)
	}
	requireVerdict(t, f.args(sessA), "TAMPERED", 2)
}

func TestSessionVerify_SingleRowMutationFlips(t *testing.T) {
	// Baseline is PROTECTED, so each flip is caused by the one mutation.
	f := newSessionFixture(t)
	requireVerdict(t, f.args(sessA), "PROTECTED", 0)
	lockExec(t, f.lockDB, "UPDATE events SET detail='/tmp/harmless' WHERE id=3")
	requireVerdict(t, f.args(sessA), "TAMPERED", 2)

	g := newSessionFixture(t)
	requireVerdict(t, g.args(sessA), "PROTECTED", 0)
	tamperAuditFile(t, g.guardPath) // one line: decision deny -> allow
	requireVerdict(t, g.args(sessA), "TAMPERED", 2)

	// A mutation to a row of ANOTHER session still flips: the chains span sessions.
	h := newSessionFixture(t)
	lockExec(t, h.lockDB, "UPDATE events SET detail='other' WHERE id=2")
	requireVerdict(t, h.args(sessA), "TAMPERED", 2)
}

func TestSessionVerify_ForgedPrevHashValidSigFails(t *testing.T) {
	f := newSessionFixture(t)
	sigBefore := lockScalar(t, f.lockDB, "SELECT entry_sig FROM events WHERE id=3")
	// Re-link row 3 onto row 1 (skipping row 2). entry_sig covers the canonical
	// bytes only, so row 3's signature stays valid under the key.
	row1 := lockScalar(t, f.lockDB, "SELECT entry_hash FROM events WHERE id=1")
	lockExec(t, f.lockDB, "UPDATE events SET prev_hash=? WHERE id=3", row1)
	if got := lockScalar(t, f.lockDB, "SELECT entry_sig FROM events WHERE id=3"); got != sigBefore || got == "" {
		t.Fatalf("fixture error: row 3 signature changed")
	}
	lockPub, _ := hex.DecodeString(os.Getenv(lockEnv))
	r, _ := receipt.VerifySession(f.lockDB, ed25519.PublicKey(lockPub), sessA)
	var row3SigOK bool
	for _, rr := range r.Rows {
		if rr.ID == 3 {
			row3SigOK = rr.SigOK
		}
	}
	if !row3SigOK {
		t.Fatalf("fixture error: row 3 signature must still verify; the forgery is the link only (rows=%+v)", r.Rows)
	}
	requireVerdict(t, f.args(sessA), "TAMPERED", 2)
}

// writeHandSignedGuardTrail writes a Guard trail signed with priv exactly the
// way audit.Auditor does (sig = Ed25519(canon || "\n" || prevSig); signed .hwm),
// but with a caller-chosen key_id. The Auditor never lets a caller set key_id,
// so this is the only way to get a line whose signature verifies while its
// key_id names another key.
func writeHandSignedGuardTrail(t *testing.T, path string, priv ed25519.PrivateKey, events []audit.Event) {
	t.Helper()
	var buf strings.Builder
	prev := ""
	for _, ev := range events {
		ev.Sig = ""
		canon, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		msg := append(append(append([]byte{}, canon...), '\n'), prev...)
		ev.Sig = hex.EncodeToString(ed25519.Sign(priv, msg))
		line, _ := json.Marshal(ev)
		buf.Write(line)
		buf.WriteByte('\n')
		prev = ev.Sig
	}
	if err := os.WriteFile(path, []byte(buf.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	hwmMsg := []byte(fmt.Sprintf("nockguard-hwm-v1\n%d\n%s\n", len(events), prev))
	hwm, _ := json.Marshal(map[string]any{"count": len(events), "last_sig": prev, "sig": hex.EncodeToString(ed25519.Sign(priv, hwmMsg))})
	if err := os.WriteFile(path+".hwm", append(hwm, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSessionVerify_GuardKeyIDMismatchFails(t *testing.T) {
	f := newSessionFixture(t)
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.dir, "handsigned.audit.jsonl")
	good := fp(f.guardPub)

	// Control: correct key_id on every line verifies PROTECTED, proving the
	// hand signer matches the real chain format.
	writeHandSignedGuardTrail(t, path, f.guardPriv, []audit.Event{
		{Time: "2026-09-25T12:00:00Z", Agent: "coder", Tool: "Read", Decision: "allow", SessionID: sessA, KeyID: good},
		{Time: "2026-09-25T12:00:01Z", Agent: "coder", Tool: "Bash", Decision: "deny", SessionID: sessA, KeyID: good},
	})
	if _, err := audit.VerifyEd25519(path, f.guardPub); err != nil {
		t.Fatalf("fixture error: hand-signed trail does not verify: %v", err)
	}
	f.guardPath = path
	requireVerdict(t, f.args(sessA), "PROTECTED", 0)

	// Same chain, valid signatures, but one session line names another key.
	writeHandSignedGuardTrail(t, path, f.guardPriv, []audit.Event{
		{Time: "2026-09-25T12:00:00Z", Agent: "coder", Tool: "Read", Decision: "allow", SessionID: sessA, KeyID: good},
		{Time: "2026-09-25T12:00:01Z", Agent: "coder", Tool: "Bash", Decision: "deny", SessionID: sessA, KeyID: fp(otherPub)},
	})
	if _, err := audit.VerifyEd25519(path, f.guardPub); err != nil {
		t.Fatalf("fixture error: mismatch trail must still verify its signatures: %v", err)
	}
	out := requireVerdict(t, f.args(sessA), "TAMPERED", 2)
	if !strings.Contains(out, "key_id") {
		t.Fatalf("key_id mismatch must be named in the output:\n%s", out)
	}

	// A mismatched key_id on a line of ANOTHER session in the same trail also fails.
	writeHandSignedGuardTrail(t, path, f.guardPriv, []audit.Event{
		{Time: "2026-09-25T12:00:00Z", Agent: "coder", Tool: "Read", Decision: "allow", SessionID: sessA, KeyID: good},
		{Time: "2026-09-25T12:00:01Z", Agent: "coder", Tool: "Read", Decision: "allow", SessionID: sessB, KeyID: fp(otherPub)},
	})
	requireVerdict(t, f.args(sessA), "TAMPERED", 2)
}

func TestSessionVerify_MissingFlagIsError(t *testing.T) {
	f := newSessionFixture(t)
	full := f.args(sessA)
	cases := map[string][]string{
		"no session value": {"verify", "--session"},
		"no lock db":       {"verify", "--session", sessA, "--guard-trail", f.guardPath, "--pub-env", lockEnv},
		"no guard trail":   {"verify", "--session", sessA, "--lock-db", f.lockDB, "--pub-env", lockEnv},
		"no key":           {"verify", "--session", sessA, "--lock-db", f.lockDB, "--guard-trail", f.guardPath},
		"only lock key":    {"verify", "--session", sessA, "--lock-db", f.lockDB, "--guard-trail", f.guardPath, "--lock-pub-env", lockEnv},
		"pub-env + split":  append(append([]string{}, full...), "--pub-env", lockEnv),
		"empty session":    {"verify", "--session", "", "--lock-db", f.lockDB, "--guard-trail", f.guardPath, "--pub-env", lockEnv},
		"unset key env":    {"verify", "--session", sessA, "--lock-db", f.lockDB, "--guard-trail", f.guardPath, "--pub-env", "TEST_NOCKGUARD_UNSET_ENV"},
		"unknown flag":     append(append([]string{}, full...), "--audit-dir", f.dir),
	}
	for name, args := range cases {
		code, stdout, stderr := runCommandForTest(t, args...)
		if code != 1 {
			t.Fatalf("%s: exit=%d, want 1\nstdout:\n%s\nstderr:\n%s", name, code, stdout, stderr)
		}
		if strings.Contains(stdout, "PROTECTED") {
			t.Fatalf("%s: a usage error printed PROTECTED:\n%s", name, stdout)
		}
		if stderr == "" {
			t.Fatalf("%s: usage error must explain itself on stderr", name)
		}
	}
}

func TestSessionVerify_JSON(t *testing.T) {
	type chain struct {
		Path         string `json:"path"`
		Verdict      string `json:"verdict"`
		KeyID        string `json:"key_id"`
		Rows         int    `json:"rows"`
		TailVerified bool   `json:"tail_verified"`
		Reason       string `json:"reason"`
	}
	type out struct {
		Verdict      string `json:"verdict"`
		SessionID    string `json:"session_id"`
		Lock         chain  `json:"lock"`
		Guard        chain  `json:"guard"`
		RollbackNote string `json:"rollback_note"`
	}
	f := newSessionFixture(t)
	lockPub, _ := hex.DecodeString(os.Getenv(lockEnv))

	code, stdout, stderr := runCommandForTest(t, f.args(sessA, "--json")...)
	var got out
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s\n%s", err, stdout, stderr)
	}
	if code != 0 || got.Verdict != "PROTECTED" || got.SessionID != sessA {
		t.Fatalf("json intact: exit=%d %+v", code, got)
	}
	if got.Lock.Verdict != "INTACT" || got.Lock.Rows != 3 || !got.Lock.TailVerified || got.Lock.KeyID != fp(lockPub) || got.Lock.Path != f.lockDB {
		t.Fatalf("json lock detail wrong: %+v", got.Lock)
	}
	if got.Guard.Verdict != "INTACT" || got.Guard.Rows != 3 || !got.Guard.TailVerified || got.Guard.KeyID != fp(f.guardPub) || got.Guard.Path != f.guardPath {
		t.Fatalf("json guard detail wrong: %+v", got.Guard)
	}
	if !strings.Contains(got.RollbackNote, "--against-remote-anchor") {
		t.Fatalf("json must carry the rollback residual note: %q", got.RollbackNote)
	}

	// One tampered chain: unified TAMPERED, the other chain still INTACT.
	lockExec(t, f.lockDB, "UPDATE events SET detail='x' WHERE id=4")
	code, stdout, _ = runCommandForTest(t, f.args(sessA, "--json")...)
	got = out{}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if code != 2 || got.Verdict != "TAMPERED" || got.Lock.Verdict != "TAMPERED" || got.Lock.Reason == "" || got.Guard.Verdict != "INTACT" {
		t.Fatalf("json tampered: exit=%d %+v", code, got)
	}
}

// forgedSessionLine is a session-a line that no key signed.
func forgedSessionLine(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(audit.Event{Time: "2026-09-25T12:00:09Z", Agent: "coder", Tool: "Bash", Decision: "allow", SessionID: sessA})
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func TestSessionVerify_SnapshotVerifyAndSelectSameBytes(t *testing.T) {
	f := newSessionFixture(t)
	trail, err := os.ReadFile(f.guardPath)
	if err != nil {
		t.Fatal(err)
	}
	hwm, err := os.ReadFile(f.guardPath + ".hwm")
	if err != nil {
		t.Fatal(err)
	}
	if c := verifyGuardSnapshot(trail, hwm, f.guardPub, sessA); c.Verdict != "INTACT" || c.Rows != 3 || !c.TailVerified {
		t.Fatalf("genuine snapshot: %+v, want INTACT/3 rows/tail verified", c)
	}
	lines := strings.SplitAfter(strings.TrimRight(string(trail), "\n"), "\n")

	// Same line count, one genuine line replaced by an unsigned session line:
	// the swap an attacker would stage between verify and select.
	swapped := strings.Join(append(append([]string{}, lines[:2]...), append([]string{string(forgedSessionLine(t))}, lines[3:]...)...), "")
	if c := verifyGuardSnapshot([]byte(swapped), hwm, f.guardPub, sessA); c.Verdict == "INTACT" || c.Verdict != "TAMPERED" {
		t.Fatalf("unsigned session line in the snapshot: %+v, want TAMPERED", c)
	}

	// An extra unsigned session line inserted mid-trail.
	inserted := strings.Join(append(append([]string{}, lines[:1]...), append([]string{string(forgedSessionLine(t))}, lines[1:]...)...), "")
	if c := verifyGuardSnapshot([]byte(inserted), hwm, f.guardPub, sessA); c.Verdict != "TAMPERED" {
		t.Fatalf("inserted unsigned session line: %+v, want TAMPERED", c)
	}

	// A session line validly signed, but by another key.
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	other := filepath.Join(f.dir, "other.audit.jsonl")
	writeHandSignedGuardTrail(t, other, otherPriv, []audit.Event{
		{Time: "2026-09-25T12:00:00Z", Agent: "coder", Tool: "Bash", Decision: "allow", SessionID: sessA},
	})
	ob, _ := os.ReadFile(other)
	oh, _ := os.ReadFile(other + ".hwm")
	if c := verifyGuardSnapshot(ob, oh, f.guardPub, sessA); c.Verdict != "TAMPERED" {
		t.Fatalf("session line signed by another key: %+v, want TAMPERED", c)
	}

	// Rows present but the sidecar missing from the snapshot.
	if c := verifyGuardSnapshot(trail, nil, f.guardPub, sessA); c.Verdict != "TAMPERED" {
		t.Fatalf("snapshot without .hwm: %+v, want TAMPERED", c)
	}
}

// TestSessionVerify_GuardTrailReadOnce swaps the trail on disk the instant it is
// opened (rename over the path, same line count, forged session rows) and
// deletes the .hwm the instant it is opened. The verdict must reflect the one
// snapshot taken, and each Guard path must be opened exactly once.
func TestSessionVerify_GuardTrailReadOnce(t *testing.T) {
	f := newSessionFixture(t)
	genuine, err := os.ReadFile(f.guardPath)
	if err != nil {
		t.Fatal(err)
	}
	// Forged replacement: 4 lines like the genuine trail, all unsigned session-a.
	forged := filepath.Join(f.dir, "forged.jsonl")
	var fb []byte
	for i := 0; i < strings.Count(string(genuine), "\n"); i++ {
		fb = append(fb, forgedSessionLine(t)...)
	}
	if err := os.WriteFile(forged, fb, 0o644); err != nil {
		t.Fatal(err)
	}

	opens := map[string]int{}
	orig := guardSnapshotOpen
	t.Cleanup(func() { guardSnapshotOpen = orig })
	guardSnapshotOpen = func(name string) (*os.File, error) {
		fh, err := orig(name)
		opens[name]++
		switch name {
		case f.guardPath:
			if rerr := os.Rename(forged, f.guardPath); rerr != nil {
				t.Errorf("swap trail: %v", rerr)
			}
		case f.guardPath + ".hwm":
			if rerr := os.Remove(name); rerr != nil {
				t.Errorf("remove hwm: %v", rerr)
			}
		}
		return fh, err
	}

	code, stdout, stderr := runCommandForTest(t, f.args(sessA, "--json")...)
	var got struct {
		Verdict string `json:"verdict"`
		Guard   struct {
			Verdict string `json:"verdict"`
			Rows    int    `json:"rows"`
		} `json:"guard"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s\n%s", err, stdout, stderr)
	}
	if opens[f.guardPath] != 1 || opens[f.guardPath+".hwm"] != 1 {
		t.Fatalf("guard files opened %v, want each exactly once", opens)
	}
	if code != 0 || got.Verdict != "PROTECTED" || got.Guard.Verdict != "INTACT" || got.Guard.Rows != 3 {
		t.Fatalf("verdict must reflect the snapshot (PROTECTED, 3 genuine rows), got exit=%d %+v\n%s", code, got, stdout)
	}
}

func TestSessionVerify_GuardSymlinkRefused(t *testing.T) {
	f := newSessionFixture(t)
	link := filepath.Join(f.dir, "link.audit.jsonl")
	if err := os.Symlink(f.guardPath, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	f.guardPath = link
	out := requireVerdict(t, f.args(sessA), "UNVERIFIABLE", 1)
	if !strings.Contains(out, "symlink") {
		t.Fatalf("symlinked trail must be refused as a symlink:\n%s", out)
	}
}

// TestSessionVerify_AppendBetweenSnapshotsIsNotTampered: a genuine Record
// (entry append, then .hwm advance) lands between the two Guard snapshot reads.
// That is legitimate concurrent writing, not tampering, so the verdict must be
// PROTECTED with the rows of the trail snapshot.
func TestSessionVerify_AppendBetweenSnapshotsIsNotTampered(t *testing.T) {
	f := newSessionFixture(t)
	opens := 0
	orig := guardSnapshotOpen
	t.Cleanup(func() { guardSnapshotOpen = orig })
	guardSnapshotOpen = func(name string) (*os.File, error) {
		opens++
		if opens == 2 {
			// The first snapshot is taken; the second is not yet opened.
			a, err := audit.New(f.guardPath, audit.WithEd25519Key(f.guardPriv))
			if err != nil {
				t.Errorf("audit.New for concurrent append: %v", err)
			} else {
				if err := a.Record(audit.Event{Agent: "coder", Tool: "Edit", Decision: "allow", SessionID: sessA}); err != nil {
					t.Errorf("concurrent Record: %v", err)
				}
				_ = a.Close()
			}
		}
		return orig(name)
	}

	code, stdout, stderr := runCommandForTest(t, f.args(sessA, "--json")...)
	var got struct {
		Verdict string `json:"verdict"`
		Guard   struct {
			Verdict string `json:"verdict"`
			Rows    int    `json:"rows"`
			Reason  string `json:"reason"`
		} `json:"guard"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s\n%s", err, stdout, stderr)
	}
	if opens != 2 {
		t.Fatalf("guard snapshot opens = %d, want 2 (.hwm and trail, once each)", opens)
	}
	// The appended entry lies beyond the checkpoint snapshotted first, so the
	// Guard tail is not proven: UNANCHORED (exit 1), never TAMPERED or PROTECTED.
	if code != 1 || got.Verdict != "UNANCHORED" || got.Guard.Verdict != "UNANCHORED" || got.Guard.Rows != 4 {
		t.Fatalf("append between snapshots: exit=%d verdict=%s guard=%+v, want UNANCHORED/exit 1 with 4 session rows", code, got.Verdict, got.Guard)
	}
	if !strings.Contains(got.Guard.Reason, "beyond the signed checkpoint") {
		t.Fatalf("UNANCHORED reason must name the entries beyond the checkpoint: %q", got.Guard.Reason)
	}
}

// TestSessionVerify_RowsBeyondCheckpointAreUnanchored: a genuine, correctly
// chained and signed entry sits past the .hwm count (a crash between the
// append and the checkpoint update, or a writer mid-append). Every signature
// verifies, but the suffix is not covered by the signed checkpoint, so the
// Guard tail is UNANCHORED, including for a session that lives only there.
func TestSessionVerify_RowsBeyondCheckpointAreUnanchored(t *testing.T) {
	f := newSessionFixture(t)
	oldHWM, err := os.ReadFile(f.guardPath + ".hwm")
	if err != nil {
		t.Fatal(err)
	}
	a, err := audit.New(f.guardPath, audit.WithEd25519Key(f.guardPriv))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Record(audit.Event{Agent: "coder", Tool: "Edit", Decision: "allow", SessionID: "session-c"}); err != nil {
		t.Fatal(err)
	}
	_ = a.Close()
	if err := os.WriteFile(f.guardPath+".hwm", oldHWM, 0o644); err != nil {
		t.Fatal(err)
	}
	if n, err := audit.VerifyEd25519(f.guardPath, f.guardPub); err != nil || n != 5 {
		t.Fatalf("fixture error: the suffix must be genuine (verifier passes 5 entries), n=%d err=%v", n, err)
	}

	out := requireVerdict(t, f.args(sessA), "UNANCHORED", 1)
	if !strings.Contains(out, "1 entries beyond the signed checkpoint (count 4)") {
		t.Fatalf("UNANCHORED output must name the suffix:\n%s", out)
	}
	// session-c has rows ONLY in the unanchored suffix; the Lock chain has none,
	// so the unified verdict is the worse NO_ROWS, and the Guard side must still
	// read UNANCHORED rather than INTACT.
	code, stdout, _ := runCommandForTest(t, f.args("session-c", "--json")...)
	var got struct {
		Verdict string `json:"verdict"`
		Guard   struct {
			Verdict      string `json:"verdict"`
			Rows         int    `json:"rows"`
			TailVerified bool   `json:"tail_verified"`
		} `json:"guard"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if code == 0 || got.Verdict == "PROTECTED" || got.Guard.Verdict != "UNANCHORED" || got.Guard.Rows != 1 || got.Guard.TailVerified {
		t.Fatalf("suffix-only session: exit=%d %+v, want not PROTECTED with Guard UNANCHORED over 1 row", code, got)
	}
}
