package approval

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// shortDir keeps the socket path under the unix sun_path limit.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "ng")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return filepath.Join(d, "approvals")
}

func startLocal(t *testing.T, timeout time.Duration) (*LocalApprover, string) {
	t.Helper()
	dir := shortDir(t)
	a, err := NewLocalApprover(dir, timeout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.ln.Close() })
	return a, dir
}

func askAsync(a *LocalApprover) chan Verdict {
	ch := make(chan Verdict, 1)
	go func() {
		ch <- a.Ask(Request{Agent: "kit", Tool: "deploy_prod", Reason: "ask rule", Params: []byte(`{"arguments":{"secret":"hunter2"}}`)})
	}()
	return ch
}

func waitPending(t *testing.T, dir string) Pending {
	t.Helper()
	for i := 0; i < 200; i++ {
		if h, _ := ListPending(dir); len(h) == 1 {
			return h[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("held call never listed")
	return Pending{}
}

func TestLocalApproveAndDeny(t *testing.T) {
	for _, approve := range []bool{true, false} {
		a, dir := startLocal(t, 5*time.Second)
		got := askAsync(a)
		h := waitPending(t, dir)
		if h.Agent != "kit" || h.Tool != "deploy_prod" || h.Reason != "ask rule" {
			t.Fatalf("listing wrong: %+v", h)
		}
		select {
		case v := <-got:
			t.Fatalf("Ask returned %+v before any decision", v)
		case <-time.After(50 * time.Millisecond):
		}
		if err := Decide(dir, h.ID, approve); err != nil {
			t.Fatal(err)
		}
		v := <-got
		want := "local:" + itoa(os.Getuid())
		if v.Approved != approve || !strings.HasSuffix(v.Reason, want) {
			t.Errorf("approve=%v: got %+v, want approver %s", approve, v, want)
		}
		if err := Decide(dir, h.ID, true); err == nil {
			t.Error("a decided call must not be decidable twice")
		}
	}
}

func TestLocalListNeverLeaksArguments(t *testing.T) {
	a, dir := startLocal(t, 5*time.Second)
	askAsync(a)
	h := waitPending(t, dir)
	if strings.Contains(strings.Join([]string{h.ID, h.Agent, h.Tool, h.Reason}, "|"), "hunter2") {
		t.Fatal("listing leaked arguments")
	}
	raw, err := localCall(filepath.Join(dir, itoa(os.Getpid())+".sock"), localMsg{Op: "list"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mustJSON(raw)), "hunter2") {
		t.Fatal("wire listing leaked arguments")
	}
}

func TestLocalTimeoutDenies(t *testing.T) {
	a, _ := startLocal(t, 50*time.Millisecond)
	v := a.Ask(Request{Agent: "kit", Tool: "deploy_prod"})
	if v.Approved || v.Reason != "timeout" {
		t.Errorf("got %+v, want timeout deny", v)
	}
}

func TestLocalRefusesBadPermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0o755, 0o770, 0o500} {
		dir := shortDir(t)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if a, err := NewLocalApprover(dir, time.Second); err == nil {
			a.ln.Close()
			t.Errorf("dir mode %04o: approver started, want refusal", mode)
		}
	}
	// Positive control: the same path with 0700 starts.
	dir := shortDir(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	a, err := NewLocalApprover(dir, time.Second)
	if err != nil {
		t.Fatalf("0700 dir must start: %v", err)
	}
	a.ln.Close()
}

func TestLocalRefusesSymlinkDir(t *testing.T) {
	real := shortDir(t)
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := real + "-link"
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if a, err := NewLocalApprover(link, time.Second); err == nil {
		a.ln.Close()
		t.Error("symlinked approvals dir must be refused")
	}
}

func TestLocalSocketIs0600(t *testing.T) {
	a, dir := startLocal(t, time.Second)
	_ = a
	fi, err := os.Lstat(filepath.Join(dir, itoa(os.Getpid())+".sock"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v, err %v", fi.Mode(), err)
	}
}

func TestLocalGarbageDoesNotDecide(t *testing.T) {
	a, dir := startLocal(t, 5*time.Second)
	got := askAsync(a)
	h := waitPending(t, dir)
	c, err := net.Dial("unix", filepath.Join(dir, itoa(os.Getpid())+".sock"))
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("not json\n"))
	c.Close()
	if err := Decide(dir, "x-1", true); err == nil {
		t.Error("malformed id must fail")
	}
	select {
	case v := <-got:
		t.Fatalf("garbage decided the call: %+v", v)
	case <-time.After(50 * time.Millisecond):
	}
	_ = Decide(dir, h.ID, false)
}

func itoa(i int) string { return strconv.Itoa(i) }

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// A decision that lands after the timer fires but before Ask checks the hold
// was reported OK to the operator, so it must be the verdict.
func TestLocalTimeoutRaceHonorsReportedDecision(t *testing.T) {
	a, dir := startLocal(t, 50*time.Millisecond)
	a.beforeTimeoutCheck = func() {
		h := waitPending(t, dir)
		if err := Decide(dir, h.ID, true); err != nil {
			t.Errorf("decide in the race window: %v", err)
		}
	}
	if v := <-askAsync(a); !v.Approved {
		t.Errorf("operator was told OK but the call was %+v", v)
	}
}

// Negative control: once the timeout owns the hold, a late decide is refused.
func TestLocalLateDecideAfterTimeoutIsRefused(t *testing.T) {
	a, dir := startLocal(t, 50*time.Millisecond)
	got := askAsync(a)
	h := waitPending(t, dir)
	if v := <-got; v.Approved || v.Reason != "timeout" {
		t.Fatalf("want timeout, got %+v", v)
	}
	if err := Decide(dir, h.ID, true); err == nil {
		t.Error("decide after timeout reported success")
	}
}

func TestLocalStartupStaleSocketCleanup(t *testing.T) {
	uid := uint32(os.Getuid())
	dir := filepath.Dir(shortDir(t))
	// regular file: refused, left in place
	f := filepath.Join(dir, "f.sock")
	os.WriteFile(f, nil, 0o600)
	if err := clearStaleSocket(f, uid); err == nil {
		t.Error("removed a regular file")
	}
	if _, err := os.Lstat(f); err != nil {
		t.Error("regular file was deleted")
	}
	// dead socket (listener closed, file left behind): removed
	s := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", s)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	if err := clearStaleSocket(s, uid); err != nil {
		t.Errorf("stale socket not cleared: %v", err)
	}
	if _, err := os.Lstat(s); err == nil {
		t.Error("stale socket still present")
	}
}

func TestLocalListPendingDoesNotUnlinkDeadSockets(t *testing.T) {
	_, dir := startLocal(t, time.Second)
	s := filepath.Join(dir, "99999.sock")
	ln, err := net.Listen("unix", s)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	os.Chmod(s, 0o600)
	if _, err := ListPending(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(s); err != nil {
		t.Error("ListPending unlinked a socket")
	}
}

func TestLocalCLIRefusesSymlinkedDirAndForeignServer(t *testing.T) {
	real := filepath.Dir(shortDir(t))
	link := filepath.Join(filepath.Dir(shortDir(t)), "approvals")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ListPending(link); err == nil {
		t.Error("ListPending followed a symlinked approvals dir")
	}
	if err := Decide(link, "1-1", true); err == nil {
		t.Error("Decide followed a symlinked approvals dir")
	}
	// loose perms on the approvals dir
	loose := shortDir(t)
	os.Mkdir(loose, 0o755)
	os.Chmod(loose, 0o755)
	if _, err := ListPending(loose); err == nil {
		t.Error("ListPending accepted a 0755 dir")
	}
}

func TestLocalAcceptTemporary(t *testing.T) {
	if !acceptTemporary(syscall.EMFILE) || acceptTemporary(errors.New("boom")) {
		t.Error("acceptTemporary misclassifies")
	}
}

func TestLocalRefusesLiveSocketOfSamePid(t *testing.T) {
	_, dir := startLocal(t, time.Second)
	if a2, err := NewLocalApprover(dir, time.Second); err == nil {
		a2.ln.Close()
		t.Error("second approver replaced a live socket")
	}
}
