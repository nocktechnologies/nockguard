package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// runWithOpenStdin starts the proxy with the client's stdin held open and
// returns the stdin writer, a line reader on stdout, and a channel carrying
// the process exit error.
func runWithOpenStdin(t *testing.T, upstream string) (io.WriteCloser, *bufio.Scanner, <-chan error) {
	in, out, exited, _ := runWithOpenStdinStderr(t, upstream)
	return in, out, exited
}

func runWithOpenStdinStderr(t *testing.T, upstream string, policyPath ...string) (io.WriteCloser, *bufio.Scanner, <-chan error, *lockedBuffer) {
	t.Helper()
	var policy string
	if len(policyPath) > 0 {
		policy = policyPath[0]
	} else {
		policy = writePolicyFile(t)
	}
	cmd := exec.Command(buildBinary(t), "proxy",
		"--upstream", upstream, "--agent", "kit", "--policy", policy)
	stderr := &lockedBuffer{}
	cmd.Stderr = stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	return in, bufio.NewScanner(out), exited, stderr
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func waitNonzeroExit(t *testing.T, exited <-chan error) {
	t.Helper()
	select {
	case err := <-exited:
		if err == nil {
			t.Fatal("proxy exited 0 after the upstream died; want nonzero")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxy still running after the upstream died with client stdin open")
	}
}

func waitGrandchildGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatal("grandchild still running after proxy exit")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestProxyExitsWhenUpstreamDiesBeforeInitialize(t *testing.T) {
	_, _, exited := runWithOpenStdin(t, "false")
	waitNonzeroExit(t, exited)
}

func TestProxyAnswersInFlightCallWhenUpstreamDies(t *testing.T) {
	script := filepath.Join(t.TempDir(), "die-on-call.sh")
	if err := os.WriteFile(script, []byte("#!/bin/bash\nread -r line\nexit 3\n"), 0755); err != nil {
		t.Fatal(err)
	}
	in, out, exited := runWithOpenStdin(t, "bash "+script)
	if _, err := io.WriteString(in, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`+"\n"); err != nil {
		t.Fatal(err)
	}

	lineCh := make(chan string, 1)
	go func() {
		if out.Scan() {
			lineCh <- out.Text()
		}
		close(lineCh)
	}()
	select {
	case line, ok := <-lineCh:
		if !ok {
			t.Fatal("stdout closed without an error response for the in-flight call")
		}
		var resp struct {
			ID    json.RawMessage `json:"id"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			t.Fatalf("bad response %q: %v", line, err)
		}
		if strings.TrimSpace(string(resp.ID)) != "7" || resp.Error == nil {
			t.Fatalf("want JSON-RPC error for id 7, got %s", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no response for the in-flight call after the upstream died")
	}
	waitNonzeroExit(t, exited)
}

func TestProxyAnswersInFlightInitializeWhenUpstreamDies(t *testing.T) {
	script := filepath.Join(t.TempDir(), "die-on-initialize.sh")
	if err := os.WriteFile(script, []byte("#!/bin/bash\nread -r line\nexit 3\n"), 0755); err != nil {
		t.Fatal(err)
	}
	in, out, exited := runWithOpenStdin(t, "bash "+script)
	if _, err := io.WriteString(in, `{"jsonrpc":"2.0","id":8,"method":"initialize"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	lineCh := make(chan string, 1)
	go func() {
		if out.Scan() {
			lineCh <- out.Text()
		}
		close(lineCh)
	}()
	select {
	case line, ok := <-lineCh:
		if !ok {
			t.Fatal("stdout closed without an error response for initialize")
		}
		var resp struct {
			ID    json.RawMessage `json:"id"`
			Error *struct{}       `json:"error"`
		}
		if err := json.Unmarshal([]byte(line), &resp); err != nil || string(resp.ID) != "8" || resp.Error == nil {
			t.Fatalf("want JSON-RPC error for initialize id 8, got %q (%v)", line, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no response for in-flight initialize")
	}
	waitNonzeroExit(t, exited)
}

// A grandchild that inherited stdout must not keep the proxy alive after the
// upstream itself has exited, and must not outlive it.
func TestProxyExitsWhenGrandchildHoldsStdout(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "grandchild.pid")
	script := filepath.Join(dir, "orphan.sh")
	body := "#!/bin/bash\nsleep 30 &\necho $! > " + pidFile + "\nexit 3\n"
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	_, _, exited := runWithOpenStdin(t, "bash "+script)
	waitNonzeroExit(t, exited)

	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	waitGrandchildGone(t, pid)
}

// A client that stops reading stdout must not keep the proxy alive after the
// upstream has exited.
func TestProxyExitsWhenClientStopsReadingStdout(t *testing.T) {
	script := filepath.Join(t.TempDir(), "flood.sh")
	// Short non-JSON lines (passed through): enough to fill the unread client
	// pipe (64 KiB) so the output loop blocks in a write, yet small enough that
	// the upstream can finish writing into its own pipe and exit.
	body := "#!/bin/bash\nyes aaaa | head -c 120000\nexit 3\n"
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	// Stdout is deliberately never read.
	_, _, exited, stderr := runWithOpenStdinStderr(t, "bash "+script)
	waitNonzeroExit(t, exited)
	if !strings.Contains(stderr.String(), "output drain deadline reached") {
		t.Fatalf("shutdown did not take the stuck-output path; stderr:\n%s", stderr.String())
	}
}

// Replies for pending calls share the same deadline as output draining. A
// client that never reads stdout must not block shutdown after its pipe fills.
func TestProxyExitsWhenPendingRepliesFillUnreadStdout(t *testing.T) {
	script := filepath.Join(t.TempDir(), "die-after-requests.sh")
	body := "#!/bin/bash\nfor ((i=0;i<3000;i++)); do IFS= read -r line || exit 2; done\nexit 3\n"
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	in, _, exited, stderr := runWithOpenStdinStderr(t, "bash "+script)
	var input strings.Builder
	for i := 0; i < 3000; i++ {
		input.WriteString(`{"jsonrpc":"2.0","id":`)
		input.WriteString(strconv.Itoa(i))
		input.WriteString(`,"method":"tools/call","params":{"name":"nockcc_nock_list"}}` + "\n")
	}
	if _, err := io.WriteString(in, input.String()); err != nil {
		t.Fatal(err)
	}
	waitNonzeroExit(t, exited)
	if !strings.Contains(stderr.String(), "client reply deadline reached") {
		t.Fatalf("shutdown did not reach the blocked-reply path; stderr:\n%s", stderr.String())
	}
}

// A grandchild that keeps writing cannot renew the shutdown period forever.
func TestProxyExitsWhenGrandchildWritesForever(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "grandchild.pid")
	script := filepath.Join(dir, "writer.sh")
	body := "#!/bin/bash\n(while :; do echo aaaa; done) &\necho $! > " + pidFile + "\nexit 3\n"
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	_, _, exited := runWithOpenStdin(t, "bash "+script)
	waitNonzeroExit(t, exited)
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	waitGrandchildGone(t, pid)
}

func TestProxyGracefulExitKillsGrandchild(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "grandchild.pid")
	script := filepath.Join(dir, "graceful.sh")
	body := "#!/bin/bash\nsleep 30 >/dev/null 2>&1 &\necho $! > " + pidFile + "\nIFS= read -r line || true\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	in, _, exited := runWithOpenStdin(t, "bash "+script)
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("graceful proxy exit failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not exit after client EOF")
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	waitGrandchildGone(t, pid)
}

func TestProxyAllowsUpstreamToFinishAfterClosingStdout(t *testing.T) {
	script := filepath.Join(t.TempDir(), "close-stdout-then-exit.sh")
	body := "#!/bin/bash\nIFS= read -r line || true\necho DONE\nexec 1>&-\nsleep 0.1\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	in, out, exited := runWithOpenStdin(t, "bash "+script)
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	if !out.Scan() || out.Text() != "DONE" {
		t.Fatalf("missing final upstream output: %q", out.Text())
	}
	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("upstream should finish cleanly after closing stdout: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not exit after upstream finished")
	}
}

func TestProxyBoundsLeaderWaitAfterCleanEOF(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	policyPath := filepath.Join(dir, "policy.yaml")
	policy := "agents:\n  kit:\n    allow:\n      - nockcc_nock_*\naudit:\n  enabled: true\n  path: " + auditPath + "\n"
	if err := os.WriteFile(policyPath, []byte(policy), 0644); err != nil {
		t.Fatal(err)
	}
	leaderFile := filepath.Join(dir, "leader.pid")
	childFile := filepath.Join(dir, "child.pid")
	closedFile := filepath.Join(dir, "closed")
	script := filepath.Join(dir, "close-stdout-and-wait.sh")
	body := "#!/bin/bash\necho $$ > " + leaderFile + "\nsleep 30 >/dev/null 2>&1 &\necho $! > " + childFile + "\nwhile IFS= read -r line; do :; done\necho DONE\nexec 1>&-\necho closed > " + closedFile + "\nwait\n"
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	in, out, exited, stderr := runWithOpenStdinStderr(t, "bash "+script, policyPath)
	readPID := func(path string) int {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		return pid
	}
	if _, err := io.WriteString(in, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`+"\n"); err != nil {
		t.Fatal(err)
	}
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	if !out.Scan() || out.Text() != "DONE" {
		t.Fatalf("want final output before clean EOF; last line %q, error %v", out.Text(), out.Err())
	}
	stdoutEOF := make(chan error, 1)
	go func() {
		if out.Scan() {
			stdoutEOF <- errors.New("unexpected output after DONE")
		} else {
			stdoutEOF <- out.Err()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(closedFile); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("upstream did not close stdout")
		}
		time.Sleep(10 * time.Millisecond)
	}
	leaderPID, childPID := readPID(leaderFile), readPID(childFile)
	groupGone := false
	t.Cleanup(func() {
		if !groupGone {
			_ = syscall.Kill(-leaderPID, syscall.SIGKILL)
		}
	})
	started := time.Now()
	shutdownDeadline := time.NewTimer(upstreamShutdownBound + 500*time.Millisecond)
	defer shutdownDeadline.Stop()
	select {
	case err := <-stdoutEOF:
		if err != nil {
			t.Fatalf("client did not read stdout to EOF: %v", err)
		}
	case <-shutdownDeadline.C:
		t.Fatal("client did not receive stdout EOF after the upstream closed it")
	}
	select {
	case err := <-exited:
		if err == nil {
			t.Fatal("proxy exited successfully while the upstream needed a forced shutdown")
		}
	case <-shutdownDeadline.C:
		t.Fatal("proxy waited without a deadline after clean output EOF")
	}
	if elapsed := time.Since(started); elapsed > upstreamShutdownBound+500*time.Millisecond {
		t.Fatalf("proxy exit took %s after output EOF", elapsed)
	}
	if !strings.Contains(stderr.String(), "leader wait deadline reached") {
		t.Fatalf("shutdown missed the clean-EOF leader wait path; stderr:\n%s", stderr.String())
	}
	if err := syscall.Kill(leaderPID, 0); err != syscall.ESRCH {
		t.Fatalf("upstream leader still alive after proxy exit: %v", err)
	}
	waitGrandchildGone(t, childPID)
	groupGone = true
	var sawDispatch, sawAllow bool
	for _, event := range readAuditFile(t, auditPath) {
		if event["tool"] != "nockcc_nock_list" {
			continue
		}
		sawDispatch = sawDispatch || event["decision"] == "dispatch"
		sawAllow = sawAllow || event["decision"] == "allow"
	}
	if !sawDispatch || !sawAllow {
		t.Fatalf("unanswered forwarded call lost audit rows: dispatch=%t allow=%t", sawDispatch, sawAllow)
	}
}

func TestProxyClosedClientStdoutKillsUpstreamGroup(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "grandchild.pid")
	grandchildGone := false
	t.Cleanup(func() {
		if grandchildGone {
			return
		}
		raw, err := os.ReadFile(pidFile)
		if err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	script := filepath.Join(dir, "write-after-eof.sh")
	body := "#!/bin/bash\nsleep 30 >/dev/null 2>&1 &\necho $! > " + pidFile + "\nIFS= read -r line || true\necho '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}'\nsleep 30\n"
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(buildBinary(t), "proxy", "--upstream", "bash "+script,
		"--agent", "kit", "--policy", writePolicyFile(t))
	stderr := &lockedBuffer{}
	cmd.Stderr = stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	_ = out.Close()
	_ = in.Close()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	waitNonzeroExit(t, exited)
	if !strings.Contains(stderr.String(), "upstream->agent") {
		t.Fatalf("want client output error, stderr: %s", stderr.String())
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	waitGrandchildGone(t, pid)
	grandchildGone = true
}

func TestProxySignalKillsGrandchild(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT} {
		t.Run(sig.String(), func(t *testing.T) {
			dir := t.TempDir()
			pidFile := filepath.Join(dir, "grandchild.pid")
			script := filepath.Join(dir, "wait.sh")
			body := "#!/bin/bash\nsleep 30 &\necho $! > " + pidFile + "\nwait\n"
			if err := os.WriteFile(script, []byte(body), 0755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(buildBinary(t), "proxy", "--upstream", "bash "+script,
				"--agent", "kit", "--policy", writePolicyFile(t))
			in, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stdout = io.Discard
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill() })
			defer in.Close()
			var pid int
			deadline := time.Now().Add(5 * time.Second)
			for pid == 0 && time.Now().Before(deadline) {
				if raw, err := os.ReadFile(pidFile); err == nil {
					pid, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
				}
				time.Sleep(10 * time.Millisecond)
			}
			if pid == 0 {
				t.Fatal("upstream grandchild did not start")
			}
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			exited := make(chan error, 1)
			go func() { exited <- cmd.Wait() }()
			waitNonzeroExit(t, exited)
			waitGrandchildGone(t, pid)
		})
	}
}

func TestProxyPreservesIgnoredSIGHUP(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "grandchild.pid")
	script := filepath.Join(dir, "wait.sh")
	body := "#!/bin/bash\nsleep 30 &\necho $! > " + pidFile + "\nwait\n"
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `trap '' HUP; exec "$@"`, "bash", buildBinary(t),
		"proxy", "--upstream", "bash "+script, "--agent", "kit", "--policy", writePolicyFile(t))
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	defer in.Close()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	var pid int
	deadline := time.Now().Add(5 * time.Second)
	for pid == 0 && time.Now().Before(deadline) {
		if raw, err := os.ReadFile(pidFile); err == nil {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("upstream grandchild did not start")
	}
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		t.Fatalf("proxy exited despite inherited ignored SIGHUP: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	waitNonzeroExit(t, exited)
	waitGrandchildGone(t, pid)
}

func TestProxyDoesNotTreatStoppedUpstreamAsExited(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "leader.pid")
	script := filepath.Join(dir, "wait.sh")
	body := "#!/bin/bash\necho $$ > " + pidFile + "\nsleep 30\n"
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(buildBinary(t), "proxy", "--upstream", "bash "+script,
		"--agent", "kit", "--policy", writePolicyFile(t))
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	defer in.Close()
	var pid int
	deadline := time.Now().Add(5 * time.Second)
	for pid == 0 && time.Now().Before(deadline) {
		if raw, err := os.ReadFile(pidFile); err == nil {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("upstream leader did not start")
	}
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(pid, syscall.SIGCONT)
		_ = syscall.Kill(pid, syscall.SIGKILL)
	})
	select {
	case err := <-exited:
		t.Fatalf("proxy exited while upstream was only stopped: %v", err)
	case <-time.After(upstreamShutdownBound + 200*time.Millisecond):
	}
	_ = syscall.Kill(pid, syscall.SIGCONT)
	_ = syscall.Kill(pid, syscall.SIGKILL)
	waitNonzeroExit(t, exited)
}

// Output the upstream wrote before exiting must reach a client that is still
// reading, even when the upstream writes far more than a pipe buffer.
func TestProxyDeliversOutputWrittenBeforeUpstreamExit(t *testing.T) {
	script := filepath.Join(t.TempDir(), "burst.sh")
	body := "#!/bin/bash\nyes aaaa | head -c 4000000\necho DONE\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	in, out, exited := runWithOpenStdin(t, "bash "+script)
	_ = in.Close()
	var last string
	for out.Scan() {
		last = out.Text()
	}
	if last != "DONE" {
		t.Fatalf("output truncated; last line %q", last)
	}
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not exit")
	}
}

// A reader must keep receiving a descendant's output after the leader exits,
// even when the drain takes longer than the one-second idle bound.
func TestProxyDrainsOutputWhileClientReads(t *testing.T) {
	script := filepath.Join(t.TempDir(), "paced-output.sh")
	body := "#!/bin/bash\n(sleep 0.2; for i in {1..16}; do echo aaaa; sleep 0.1; done; echo DONE) &\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	in, out, exited := runWithOpenStdin(t, "bash "+script)
	_ = in.Close()
	started := time.Now()
	var last string
	for out.Scan() {
		last = out.Text()
	}
	if err := out.Err(); err != nil {
		t.Fatal(err)
	}
	if last != "DONE" {
		t.Fatalf("output truncated while client was reading; last line %q", last)
	}
	if elapsed := time.Since(started); elapsed < upstreamShutdownBound {
		t.Fatalf("test did not exercise output beyond the idle bound: %s", elapsed)
	}
	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("proxy failed after complete output drain: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not exit after output EOF")
	}
}
