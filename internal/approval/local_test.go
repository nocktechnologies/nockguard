package approval

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
