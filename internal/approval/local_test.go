package approval

import (
	"encoding/json"
	"errors"
	"io"
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
	d, err := os.MkdirTemp("/tmp", "ng")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return filepath.Join(d, "approvals")
}

func TestDefaultLocalDirUsesShortPathWhenHomeIsTooLong(t *testing.T) {
	home := filepath.Join("/tmp", strings.Repeat("h", 80))
	t.Setenv("HOME", home)

	dir, err := DefaultLocalDir()
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(dir, home) {
		t.Fatalf("long home path was retained: %s", dir)
	}
	if want := "nockguard-" + itoa(os.Getuid()); filepath.Base(filepath.Dir(dir)) != want {
		t.Fatalf("short approver dir = %s, want parent %s", dir, want)
	}
	if n := len(filepath.Join(dir, maxLocalSocketName)); n > maxUnixSocketPathBytes {
		t.Fatalf("maximum socket path is %d bytes, want at most %d", n, maxUnixSocketPathBytes)
	}
}

func TestNewLocalApproverRejectsLongSocketPathClearly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), strings.Repeat("x", 80), "approvals")
	_, err := NewLocalApprover(dir, time.Second)
	if err == nil {
		t.Fatal("approver started with a socket path over the safe limit")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unix socket path") || !strings.Contains(strings.ToLower(err.Error()), "too long") {
		t.Fatalf("long socket path error is unclear: %v", err)
	}
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

// pollPending is safe off the test goroutine: it reports instead of failing.
func pollPending(dir string) (Pending, bool) {
	for i := 0; i < 200; i++ {
		if h, _ := ListPending(dir); len(h) == 1 {
			return h[0], true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return Pending{}, false
}

func waitPending(t *testing.T, dir string) Pending {
	t.Helper()
	h, ok := pollPending(dir)
	if !ok {
		t.Fatal("held call never listed")
	}
	return h
}

// sockPath is the single socket under dir.
func sockPath(t *testing.T, dir string) string {
	t.Helper()
	socks, _ := filepath.Glob(filepath.Join(dir, "*.sock"))
	if len(socks) != 1 {
		t.Fatalf("want one socket in %s, got %v", dir, socks)
	}
	return socks[0]
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
		if wantActor := "local:uid:" + itoa(os.Getuid()); v.ApprovalActor != wantActor {
			t.Errorf("approve=%v: ApprovalActor = %q, want kernel peer identity %q", approve, v.ApprovalActor, wantActor)
		}
		if err := Decide(dir, h.ID, true); err == nil {
			t.Error("a decided call must not be decidable twice")
		}
	}
}

func TestLocalApprovalActorCannotBeSpoofedByJSON(t *testing.T) {
	for _, field := range []string{`"approval_actor":"local:uid:999999"`, `"Approval_Actor":"local:uid:999999"`, `"uid":999999`} {
		t.Run(field, func(t *testing.T) {
			a, dir := startLocal(t, 5*time.Second)
			got := askAsync(a)
			h := waitPending(t, dir)

			c, err := net.Dial("unix", sockPath(t, dir))
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := io.WriteString(c, `{"op":"decide","id":"`+h.ID+`","approve":true,`+field+"}\n")
			if writeErr != nil {
				c.Close()
				t.Fatal(writeErr)
			}
			var response localMsg
			decodeErr := json.NewDecoder(c).Decode(&response)
			c.Close()
			if decodeErr == nil || response.OK {
				t.Fatalf("identity-bearing request was not rejected: response=%+v err=%v", response, decodeErr)
			}
			if pending := waitPending(t, dir); pending.ID != h.ID {
				t.Fatalf("rejected identity request consumed hold: got %q want %q", pending.ID, h.ID)
			}
			if err := Decide(dir, h.ID, true); err != nil {
				t.Fatal(err)
			}
			select {
			case v := <-got:
				want := "local:uid:" + itoa(os.Getuid())
				if !v.Approved || v.ApprovalActor != want {
					t.Fatalf("kernel actor mismatch: verdict=%+v want %q", v, want)
				}
			case <-time.After(time.Second):
				t.Fatal("local approval did not resolve")
			}
		})
	}
}

func TestLocalListNeverLeaksArguments(t *testing.T) {
	a, dir := startLocal(t, 5*time.Second)
	askAsync(a)
	h := waitPending(t, dir)
	if strings.Contains(strings.Join([]string{h.ID, h.Agent, h.Tool, h.Reason}, "|"), "hunter2") {
		t.Fatal("listing leaked arguments")
	}
	raw, err := localCall(sockPath(t, dir), localMsg{Op: "list"})
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
	fi, err := os.Lstat(sockPath(t, dir))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v, err %v", fi.Mode(), err)
	}
}

func TestLocalGarbageDoesNotDecide(t *testing.T) {
	a, dir := startLocal(t, 5*time.Second)
	got := askAsync(a)
	h := waitPending(t, dir)
	c, err := net.Dial("unix", sockPath(t, dir))
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
// was reported OK to the operator, so it must be the verdict. The hook runs on
// the Ask goroutine, so it reports over a channel and the test goroutine fails.
func TestLocalTimeoutRaceHonorsReportedDecision(t *testing.T) {
	a, dir := startLocal(t, 50*time.Millisecond)
	hookErr := make(chan error, 1)
	a.beforeTimeoutCheck = func() {
		h, ok := pollPending(dir)
		if !ok {
			hookErr <- errors.New("held call never listed")
			return
		}
		hookErr <- Decide(dir, h.ID, true)
	}
	v := <-askAsync(a)
	if err := <-hookErr; err != nil {
		t.Fatalf("decide in the race window: %v", err)
	}
	if !v.Approved {
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

// deadSocket leaves a socket file with no listener behind, like a crashed proxy.
func deadSocket(t *testing.T, path string) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLocalListPendingDoesNotUnlinkDeadSockets(t *testing.T) {
	_, dir := startLocal(t, time.Second)
	s := filepath.Join(dir, "99999-0123456789abcdef.sock")
	deadSocket(t, s)
	if _, err := ListPending(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(s); err != nil {
		t.Error("ListPending unlinked a socket")
	}
}

func TestLocalSocketNamesAreUniqueAndClosedOnExit(t *testing.T) {
	a1, dir := startLocal(t, time.Second)
	a2, err := NewLocalApprover(dir, time.Second)
	if err != nil {
		t.Fatalf("second approver in the same process/dir: %v", err)
	}
	if a1.base == a2.base {
		t.Fatalf("socket names collide: %s", a1.base)
	}
	if !sockBase.MatchString(a1.base) || !strings.HasPrefix(a1.base, itoa(os.Getpid())+"-") {
		t.Errorf("socket name %q is not <pid>-<16 hex>", a1.base)
	}
	// Close removes only its own socket.
	if err := a2.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, a2.base+".sock")); err == nil {
		t.Error("Close left its own socket behind")
	}
	if _, err := os.Lstat(filepath.Join(dir, a1.base+".sock")); err != nil {
		t.Error("Close removed another approver's socket")
	}
}

func TestLocalPruneStale(t *testing.T) {
	_, dir := startLocal(t, time.Second) // live: must survive
	dead := filepath.Join(dir, "99999-0123456789abcdef.sock")
	deadSocket(t, dead)
	file := filepath.Join(dir, "plain.sock") // not a socket: must survive
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	removed, err := PruneStale(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != dead {
		t.Errorf("removed %v, want only %s", removed, dead)
	}
	if _, err := os.Lstat(dead); err == nil {
		t.Error("dead socket still present")
	}
	if _, err := os.Lstat(file); err != nil {
		t.Error("prune removed a regular file")
	}
	socks, _ := filepath.Glob(filepath.Join(dir, "*-*.sock"))
	if len(socks) != 1 {
		t.Errorf("live socket was pruned: %v", socks)
	}
}

// The proxy must refuse the same symlinked ~/.nockguard the client refuses, so
// the ask fails closed at startup rather than timing out.
func TestLocalProxyRefusesSymlinkedParent(t *testing.T) {
	root := filepath.Dir(shortDir(t))
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(link, "approvals")
	if a, err := NewLocalApprover(dir, time.Second); err == nil {
		a.Close()
		t.Error("proxy accepted a symlinked parent the client refuses")
	}
	if _, err := ListPending(dir); err == nil {
		t.Error("client accepted the symlinked parent")
	}
	// Positive control: the real directory works.
	a, err := NewLocalApprover(filepath.Join(real, "approvals"), time.Second)
	if err != nil {
		t.Fatalf("real parent must start: %v", err)
	}
	a.Close()
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

// Nothing may be created through a symlink: the checks run before any mkdir.
func TestLocalNothingCreatedThroughSymlink(t *testing.T) {
	root := filepath.Dir(shortDir(t))
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	// Symlinked parent: the target must stay empty.
	if a, err := NewLocalApprover(filepath.Join(link, "approvals"), time.Second); err == nil {
		a.Close()
		t.Fatal("accepted a symlinked parent")
	}
	if ents, _ := os.ReadDir(real); len(ents) != 0 {
		t.Errorf("created %d entries through the parent symlink", len(ents))
	}
	// Symlinked approvals dir: refused, target stays empty.
	parent := filepath.Join(root, "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(parent, "approvals")); err != nil {
		t.Fatal(err)
	}
	if a, err := NewLocalApprover(filepath.Join(parent, "approvals"), time.Second); err == nil {
		a.Close()
		t.Fatal("accepted a symlinked approvals dir")
	}
	if ents, _ := os.ReadDir(real); len(ents) != 0 {
		t.Errorf("created %d entries through the approvals symlink", len(ents))
	}
}

func TestLocalConcurrentFirstRunApprovers(t *testing.T) {
	// Neither the parent nor the dir exists: every approver races to create both.
	dir := filepath.Join(filepath.Dir(shortDir(t)), "p", "a")
	const n = 8
	start := make(chan struct{})
	errs := make(chan error, n)
	apps := make(chan *LocalApprover, n)
	for i := 0; i < n; i++ {
		go func() {
			<-start
			a, err := NewLocalApprover(dir, time.Second)
			if err != nil {
				errs <- err
				return
			}
			apps <- a
			errs <- nil
		}()
	}
	close(start)
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent first-run approver failed: %v", err)
		}
	}
	close(apps)
	for a := range apps {
		a.Close()
	}
	if fi, err := os.Lstat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir not 0700 after race: %v %v", fi, err)
	}
}

func TestLocalMkdirRaceStillChecksWhatExists(t *testing.T) {
	// A pre-existing dir with loose mode (what a racer's EEXIST lands on) is
	// still refused: tolerating EEXIST does not loosen the checks.
	dir := shortDir(t)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocalApprover(dir, time.Second); err == nil {
		t.Fatal("expected refusal for a 0755 dir")
	}
}
