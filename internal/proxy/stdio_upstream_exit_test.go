package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
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

func runWithOpenStdinStderr(t *testing.T, upstream string) (io.WriteCloser, *bufio.Scanner, <-chan error, *lockedBuffer) {
	t.Helper()
	cmd := exec.Command(buildBinary(t), "proxy",
		"--upstream", upstream, "--agent", "kit", "--policy", writePolicyFile(t))
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
	deadline := time.Now().Add(5 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatal("grandchild still running after the proxy exited")
		}
		time.Sleep(50 * time.Millisecond)
	}
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
	if !strings.Contains(stderr.String(), "output loop stuck") {
		t.Fatalf("shutdown did not take the stuck-output path; stderr:\n%s", stderr.String())
	}
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
