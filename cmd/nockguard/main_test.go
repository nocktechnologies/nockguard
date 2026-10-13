package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/policy"
)

func TestVerifyCommandCleanTrailProtected(t *testing.T) {
	dir := t.TempDir()
	path, pubHex := writeEd25519Trail(t, dir, "kit")
	t.Setenv(policy.AgentPubKeyEnvName("kit"), pubHex)

	code, stdout, stderr := runCommandForTest(t, "verify", "--agent", "kit", "--audit-dir", dir)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "PROTECTED") || !strings.Contains(stdout, path) {
		t.Fatalf("human output should include PROTECTED verdict and path, got:\n%s", stdout)
	}

	code, stdout, stderr = runCommandForTest(t, "verify", "--agent", "kit", "--audit-dir", dir, "--json")
	if code != 0 {
		t.Fatalf("json exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	var got struct {
		Verdict string `json:"verdict"`
		Entries int    `json:"entries_verified"`
		Path    string `json:"audit_path"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("verify --json emitted invalid JSON: %v\n%s", err, stdout)
	}
	if got.Verdict != "PROTECTED" || got.Entries != 3 || got.Path != path {
		t.Fatalf("json verdict = %+v, want PROTECTED/3/%s", got, path)
	}
}

func TestVerifyCommandAgentHonorsExplicitAuditPath(t *testing.T) {
	dir := t.TempDir()
	defaultPath, pubHex := writeEd25519Trail(t, dir, "kit")
	t.Setenv(policy.AgentPubKeyEnvName("kit"), pubHex)
	explicitPath := filepath.Join(dir, "corrupt.audit.jsonl")
	if err := os.WriteFile(explicitPath, []byte("not a valid audit row\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The default trail is valid, so a passing verdict would mean the requested file was skipped.
	if code, stdout, stderr := runCommandForTest(t, "verify", "--agent", "kit", "--audit-dir", dir, "--json"); code != 0 || !strings.Contains(stdout, defaultPath) {
		t.Fatalf("default trail exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	code, stdout, stderr := runCommandForTest(t, "verify", "--agent", "kit", "--audit-dir", dir, "--audit", explicitPath, "--json")
	if code != 2 {
		t.Fatalf("explicit corrupt trail exit %d, want 2\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	var got verifyResult
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("verify --json emitted invalid JSON: %v\n%s", err, stdout)
	}
	if got.Verdict != "TAMPERED" || got.AuditPath != explicitPath {
		t.Fatalf("explicit trail verdict = %+v, want TAMPERED at %s", got, explicitPath)
	}
	if code, stdout, stderr := runCommandForTest(t, "verify", "--agent", "kit", "--audit-dir", dir, "--audit", "", "--json"); code == 0 || !strings.Contains(stderr, "--audit requires a non-empty path") {
		t.Fatalf("empty explicit trail exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestWallSubcommandPassesFlagsToCompanionBinary(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "wall-args")
	wallPath := filepath.Join(dir, "nockguard-wall")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$NOCKGUARD_WALL_CAPTURE\"\n"
	if err := os.WriteFile(wallPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NOCKGUARD_WALL_CAPTURE", capture)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	code, stdout, stderr := runCommandForTest(t, "wall", "--agent", "coder", "--verify-ed25519-pub-env", "CUSTOM_PUB")
	if code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	got, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	if want := "--agent\ncoder\n--verify-ed25519-pub-env\nCUSTOM_PUB\n"; string(got) != want {
		t.Fatalf("Wall arguments = %q, want %q", got, want)
	}
}

func TestWallLauncherForwardsTermination(t *testing.T) {
	if os.Getenv("NOCKGUARD_WALL_TEST_CHILD") == "1" {
		os.Exit(runCLI([]string{"wall"}))
	}

	for _, tc := range []struct {
		name string
		sig  syscall.Signal
	}{{"interrupt", syscall.SIGTERM}, {"hangup", syscall.SIGHUP}} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			readyFile := filepath.Join(dir, "wall-ready")
			stoppedFile := filepath.Join(dir, "wall-stopped")
			pidFile := filepath.Join(dir, "wall-pid")
			wallPath := filepath.Join(dir, "nockguard-wall")
			script := "#!/bin/sh\necho $$ > \"$NOCKGUARD_WALL_PID_FILE\"\ntrap 'echo stopped > \"$NOCKGUARD_WALL_STOPPED_FILE\"; exit 0' TERM INT HUP\necho ready > \"$NOCKGUARD_WALL_READY_FILE\"\nwhile :; do sleep 0.1; done\n"
			if err := os.WriteFile(wallPath, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("NOCKGUARD_WALL_READY_FILE", readyFile)
			t.Setenv("NOCKGUARD_WALL_STOPPED_FILE", stoppedFile)
			t.Setenv("NOCKGUARD_WALL_PID_FILE", pidFile)
			t.Setenv("NOCKGUARD_WALL_TEST_CHILD", "1")

			cmd := exec.Command(os.Args[0], "-test.run=^TestWallLauncherForwardsTermination$")
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			finished := false
			defer func() {
				if finished {
					return
				}
				if data, err := os.ReadFile(pidFile); err == nil {
					if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
						if process, err := os.FindProcess(pid); err == nil {
							_ = process.Kill()
						}
					}
				}
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}()

			deadline := time.Now().Add(5 * time.Second)
			for {
				if _, err := os.Stat(readyFile); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("Wall child did not start")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err := cmd.Process.Signal(tc.sig); err != nil {
				t.Fatalf("send %s to launcher: %v", tc.sig, err)
			}
			if err := cmd.Wait(); err != nil {
				t.Fatalf("launcher exit after %s: %v", tc.sig, err)
			}
			finished = true
			if _, err := os.Stat(stoppedFile); err != nil {
				t.Fatalf("Wall child did not receive %s: %v", tc.sig, err)
			}
		})
	}
}

func TestKeygenHelpPrintsUsageWithoutKeyMaterial(t *testing.T) {
	code, stdout, stderr := runCommandForTest(t, "keygen", "--help")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "nockguard keygen [--agent <name>]") {
		t.Fatalf("help output should include keygen usage, got:\n%s", stderr)
	}
	output := stdout + stderr
	if strings.Contains(output, "NOCKGUARD_AUDIT_ED25519_KEY=") ||
		strings.Contains(output, "NOCKGUARD_AUDIT_ED25519_PUB=") {
		t.Fatalf("keygen --help emitted a key-material line:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}

func TestVerifyCommandTamperedTrailExit2(t *testing.T) {
	dir := t.TempDir()
	path, pubHex := writeEd25519Trail(t, dir, "kit")
	t.Setenv(policy.AgentPubKeyEnvName("kit"), pubHex)
	tamperAuditFile(t, path)

	code, stdout, stderr := runCommandForTest(t, "verify", "--agent", "kit", "--audit-dir", dir)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "TAMPER DETECTED") {
		t.Fatalf("stderr should report tamper, got:\n%s", stderr)
	}
}

func TestVerifyCommandMissingKeyExit1(t *testing.T) {
	dir := t.TempDir()
	_, _ = writeEd25519Trail(t, dir, "kit")
	t.Setenv(policy.AgentPubKeyEnvName("kit"), "")
	t.Setenv("HOME", t.TempDir())

	code, stdout, stderr := runCommandForTest(t, "verify", "--agent", "kit", "--audit-dir", dir)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "is not set") {
		t.Fatalf("stderr should report missing key, got:\n%s", stderr)
	}
}

func TestVerifyAllAgentsExitCodes(t *testing.T) {
	t.Run("all clean", func(t *testing.T) {
		dir := t.TempDir()
		_, kitPub := writeEd25519Trail(t, dir, "kit")
		_, ashPub := writeEd25519Trail(t, dir, "ash")
		t.Setenv(policy.AgentPubKeyEnvName("kit"), kitPub)
		t.Setenv(policy.AgentPubKeyEnvName("ash"), ashPub)

		code, stdout, stderr := runCommandForTest(t, "verify", "--all", "--audit-dir", dir)
		if code != 0 {
			t.Fatalf("exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
		if !strings.Contains(stdout, "PROTECTED") || !strings.Contains(stdout, "[OK]") {
			t.Fatalf("verify --all output should include protected summary and OK rows, got:\n%s", stdout)
		}
	})

	t.Run("one tampered", func(t *testing.T) {
		dir := t.TempDir()
		_, kitPub := writeEd25519Trail(t, dir, "kit")
		ashPath, ashPub := writeEd25519Trail(t, dir, "ash")
		t.Setenv(policy.AgentPubKeyEnvName("kit"), kitPub)
		t.Setenv(policy.AgentPubKeyEnvName("ash"), ashPub)
		tamperAuditFile(t, ashPath)

		code, stdout, stderr := runCommandForTest(t, "verify", "--all", "--audit-dir", dir)
		if code != 2 {
			t.Fatalf("exit code = %d, want 2\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
		if !strings.Contains(stdout, "[TAMPER]") {
			t.Fatalf("verify --all output should identify tampered trail, got:\n%s", stdout)
		}
	})

	t.Run("one unverifiable", func(t *testing.T) {
		dir := t.TempDir()
		_, kitPub := writeEd25519Trail(t, dir, "kit")
		_, _ = writeEd25519Trail(t, dir, "ash")
		t.Setenv(policy.AgentPubKeyEnvName("kit"), kitPub)
		t.Setenv(policy.AgentPubKeyEnvName("ash"), "")

		code, stdout, stderr := runCommandForTest(t, "verify", "--all", "--audit-dir", dir)
		if code != 1 {
			t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
		if !strings.Contains(stdout, "[NO KEY]") {
			t.Fatalf("verify --all output should identify unverifiable trail, got:\n%s", stdout)
		}
	})
}

// Zero audit trails means there is nothing to verify. That must never read as
// PROTECTED: an empty (or wrong) audit dir is the absence of evidence, and a
// verifier that reports it as clean is a silent success.
func TestVerifyAll_ZeroTrailsIsNotProtected(t *testing.T) {
	t.Run("text", func(t *testing.T) {
		dir := t.TempDir()
		code, stdout, stderr := runCommandForTest(t, "verify", "--all", "--audit-dir", dir)
		if code == 0 {
			t.Fatalf("exit code = 0 with zero trails, want non-zero\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
		}
		if strings.Contains(stdout, "VERDICT: PROTECTED") {
			t.Fatalf("zero trails must not print VERDICT: PROTECTED, got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "VERDICT: NO_TRAILS") {
			t.Fatalf("zero trails should print VERDICT: NO_TRAILS, got:\n%s", stdout)
		}
	})

	t.Run("json", func(t *testing.T) {
		dir := t.TempDir()
		code, stdout, stderr := runCommandForTest(t, "verify", "--all", "--json", "--audit-dir", dir)
		if code == 0 {
			t.Fatalf("exit code = 0 with zero trails, want non-zero\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
		}
		var res verifyAllResult
		if err := json.Unmarshal([]byte(stdout), &res); err != nil {
			t.Fatalf("stdout is not verifyAllResult JSON: %v\n%s", err, stdout)
		}
		if res.Verdict == "PROTECTED" {
			t.Fatalf("zero trails must not report verdict PROTECTED, got:\n%s", stdout)
		}
		if res.Verdict != "NO_TRAILS" {
			t.Fatalf("verdict = %q, want NO_TRAILS\n%s", res.Verdict, stdout)
		}
		if res.AuditDir != dir {
			t.Fatalf("audit_dir = %q, want %q", res.AuditDir, dir)
		}
		if res.Total != 0 {
			t.Fatalf("total = %d, want 0", res.Total)
		}
	})
}

func TestEvidenceCommandVerifiesBackingTrail(t *testing.T) {
	dir := t.TempDir()
	path, pubHex := writeEd25519Trail(t, dir, "kit")
	t.Setenv(policy.AgentPubKeyEnvName("kit"), pubHex)

	code, stdout, stderr := runCommandForTest(t, "evidence", "--framework", "soc2", "--agent", "kit", "--audit-dir", dir, "--format", "json")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "chain intact") {
		t.Fatalf("stderr should report intact chain, got:\n%s", stderr)
	}
	var pack struct {
		Verification struct {
			ChainIntact     bool   `json:"chain_intact"`
			EntriesVerified int    `json:"entries_verified"`
			Mode            string `json:"mode"`
		} `json:"verification"`
	}
	if err := json.Unmarshal([]byte(stdout), &pack); err != nil {
		t.Fatalf("evidence --format json emitted invalid JSON: %v\n%s", err, stdout)
	}
	if !pack.Verification.ChainIntact || pack.Verification.EntriesVerified != 3 || pack.Verification.Mode != "ed25519" {
		t.Fatalf("verification = %+v, want intact/3/ed25519", pack.Verification)
	}

	tamperAuditFile(t, path)
	code, stdout, stderr = runCommandForTest(t, "evidence", "--framework", "soc2", "--agent", "kit", "--audit-dir", dir, "--format", "json")
	if code != 2 {
		t.Fatalf("tampered exit code = %d, want 2\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "TAMPER DETECTED") {
		t.Fatalf("stderr should report tamper, got:\n%s", stderr)
	}
}

func TestPolicyProposeCommandPrintsShadowAllowlist(t *testing.T) {
	dir := t.TempDir()
	writePlainTrail(t, dir, "kit", []audit.Event{
		{Agent: "kit", Tool: "Read", Decision: "allow"},
		{Agent: "kit", Tool: "Read", Decision: "allow"},
		{Agent: "kit", Tool: "Bash", Decision: "allow"},
		{Agent: "kit", Tool: "Write", Decision: "deny"},
		{Agent: "ash", Tool: "WebSearch", Decision: "allow"},
	})

	code, stdout, stderr := runCommandForTest(t, "policy", "propose", "--agent", "kit", "--audit-dir", dir)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "shadow:") || !strings.Contains(stdout, "- Bash") || !strings.Contains(stdout, "- Read") {
		t.Fatalf("policy propose should print distinct allowed tools as shadow YAML, got:\n%s", stdout)
	}
	if strings.Contains(stdout, "Write") || strings.Contains(stdout, "WebSearch") {
		t.Fatalf("policy propose included denied or other-agent tools:\n%s", stdout)
	}
}

func TestPolicyShadowReportCommandCountsWouldDeny(t *testing.T) {
	dir := t.TempDir()
	writePlainTrail(t, dir, "kit", []audit.Event{
		{Agent: "kit", Tool: "Bash", Decision: "would-deny"},
		{Agent: "kit", Tool: "Bash", Decision: "would-deny"},
		{Agent: "kit", Tool: "Write", Decision: "would-deny"},
		{Agent: "kit", Tool: "Read", Decision: "allow"},
	})

	code, stdout, stderr := runCommandForTest(t, "policy", "shadow-report", "--agent", "kit", "--audit-dir", dir)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "Bash 2") || !strings.Contains(stdout, "Write 1") {
		t.Fatalf("shadow-report should count would-deny by tool, got:\n%s", stdout)
	}
}

func TestMCPListenRejectsNonLoopbackBind(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeMCPListenPolicy(t, dir, "")

	code, _, stderr := runCommandForTest(t,
		"mcp-listen",
		"--listen", "0.0.0.0:8790",
		"--upstream", "http://127.0.0.1:1/mcp",
		"--agent", "mira",
		"--policy", policyPath,
		"--audit", filepath.Join(dir, "audit.jsonl"),
	)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "loopback") {
		t.Fatalf("stderr should explain loopback bind rejection, got:\n%s", stderr)
	}
}

func TestMCPListenSubcommandForwardsAuditsAndShutsDown(t *testing.T) {
	binary := buildNockguardBinary(t)
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "mira.audit.jsonl")
	policyPath := writeMCPListenPolicy(t, dir, auditPath)

	var gotBody string
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
	}))
	defer upstream.Close()

	listenAddr := freeLoopbackAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, binary,
		"mcp-listen",
		"--listen", listenAddr,
		"--upstream", upstream.URL,
		"--agent", "mira",
		"--policy", policyPath,
		"--audit", auditPath,
	)
	stderr := &syncBuffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start mcp-listen: %v", err)
	}
	defer func() {
		cancel()
		_ = cmd.Wait()
	}()

	waitForTCP(t, listenAddr)

	req, err := http.NewRequest(http.MethodPost, "http://"+listenAddr, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST through mcp-listen failed: %v\nstderr:\n%s", err, stderr.String())
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"ok":true`) {
		t.Fatalf("listener response status=%d body=%s\nstderr:\n%s", resp.StatusCode, body, stderr.String())
	}
	if !strings.Contains(gotBody, `"nockcc_nock_list"`) {
		t.Fatalf("upstream did not receive canonical tools/call body: %s", gotBody)
	}
	if gotAuth != "Bearer test-token" {
		t.Fatalf("upstream Authorization = %q, want connector header passthrough", gotAuth)
	}

	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("interrupt mcp-listen: %v", err)
	}
	waitForCommandExit(t, cmd, stderr)

	events := readAuditEvents(t, auditPath)
	if len(events) != 2 {
		t.Fatalf("audit rows = %d, want dispatch and allow: %+v", len(events), events)
	}
	if events[0].Decision != "dispatch" || events[1].Agent != "mira" || events[1].Tool != "nockcc_nock_list" || events[1].Decision != "allow" {
		t.Fatalf("audit rows = %+v, want dispatch then mira/nockcc_nock_list/allow", events)
	}
}

func TestStatusShowsAuditFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.audit.jsonl")
	if err := os.Mkdir(path+".audit-failing", 0700); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runCommandForTest(t, "status", "--agent", "mira", "--audit", path)
	if code != 2 || !strings.Contains(out, "last required audit write failed") || strings.Contains(out, "calls refused") {
		t.Fatalf("status = (%d, %q), want visible degraded state", code, out)
	}
	if err := os.Remove(path + ".audit-failing"); err != nil {
		t.Fatal(err)
	}
	code, out, _ = runCommandForTest(t, "doctor", "--agent", "mira", "--audit", path)
	if code != 0 || strings.Contains(out, "last required audit write failed") {
		t.Fatalf("doctor after recovery = (%d, %q)", code, out)
	}
}

func runCommandForTest(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = stdoutW
	os.Stderr = stderrW
	stdoutDone := make(chan string)
	stderrDone := make(chan string)
	go func() {
		b, _ := io.ReadAll(stdoutR)
		stdoutDone <- string(b)
	}()
	go func() {
		b, _ := io.ReadAll(stderrR)
		stderrDone <- string(b)
	}()

	code := runCLI(args)

	_ = stdoutW.Close()
	_ = stderrW.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr
	return code, <-stdoutDone, <-stderrDone
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func writeMCPListenPolicy(t *testing.T, dir, auditPath string) string {
	t.Helper()
	policyPath := filepath.Join(dir, "policy.yaml")
	content := ""
	if auditPath != "" {
		content = "audit:\n  enabled: true\n  path: " + auditPath + "\n"
	}
	content += "agents:\n  mira:\n    mode: allow\n"
	if err := os.WriteFile(policyPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return policyPath
}

func buildNockguardBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "nockguard")
	cmd := exec.Command("go", "build", "-o", binary, "./cmd/nockguard/")
	cmd.Dir = filepath.Join(mustGetwd(t), "..", "..")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return binary
}

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback address: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close reserved listener: %v", err)
	}
	return addr
}

func waitForTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to accept TCP", addr)
}

func waitForCommandExit(t *testing.T, cmd *exec.Cmd, stderr *syncBuffer) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("mcp-listen exited after interrupt with error: %v\nstderr:\n%s", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("mcp-listen did not shut down after interrupt\nstderr:\n%s", stderr.String())
	}
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}

func readAuditEvents(t *testing.T, path string) []audit.Event {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	var out []audit.Event
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("unmarshal audit row %q: %v", line, err)
		}
		out = append(out, ev)
	}
	return out
}

func writePlainTrail(t *testing.T, dir, agent string, events []audit.Event) string {
	t.Helper()
	path := policy.AgentAuditPath(filepath.Join(dir, filepath.Base(policy.DefaultAuditPath)), agent)
	a, err := audit.New(path)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	for _, ev := range events {
		if err := a.Record(ev); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

func writeEd25519Trail(t *testing.T, dir, agent string) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	basePath := filepath.Join(dir, filepath.Base(policy.DefaultAuditPath))
	path := policy.AgentAuditPath(basePath, agent)
	a, err := audit.New(path, audit.WithEd25519Key(priv))
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	events := []audit.Event{
		{Agent: agent, Tool: "Read", Decision: "allow"},
		{Agent: agent, Tool: "Bash", Decision: "deny", Reason: "policy"},
		{Agent: agent, Tool: "nockcc_kill_switch_set", Decision: "approval-granted", Reason: "human ok"},
	}
	for _, ev := range events {
		if err := a.Record(ev); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path, hex.EncodeToString(pub)
}

func tamperAuditFile(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), `"decision":"deny"`, `"decision":"allow"`, 1)
	if tampered == string(data) {
		t.Fatal("tamper substitution did not match")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyCheckLoadOnly(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct {
		name, body string
		want       int
	}{
		{"valid", "agents:\n  default:\n    mode: deny\n", 0},
		{"unknown-key", "agents:\n  default:\n    mod: deny\n", 1},
		{"malformed-glob", "agents:\n  default:\n    allow: [\"[\"]\n", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runCommandForTest(t, "policy", "check", "--policy", write(tc.name+".yaml", tc.body))
			if code != tc.want {
				t.Fatalf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tc.want, stdout, stderr)
			}
			if tc.want == 1 && !strings.Contains(stderr, "error:") {
				t.Fatalf("load error not printed, stderr:\n%s", stderr)
			}
		})
	}
	dup := "agents:\n  test:\n    mode: allow\n    inject:\n" +
		"      - tools: [\"github_create_issue\", \"github_list_issues\"]\n        ref: \"env:T1\"\n        arg: \"headers.a\"\n" +
		"      - tools: [\"github_create_issue\"]\n        ref: \"env:T2\"\n        arg: \"headers.b\"\n"
	code, _, stderr := runCommandForTest(t, "policy", "check", "--policy", write("dup-inject.yaml", dup))
	if code != 0 || !strings.Contains(stderr, "warning policy:") || !strings.Contains(stderr, "github_create_issue") {
		t.Fatalf("duplicate inject tool: exit = %d, want 0 with a warning, stderr:\n%s", code, stderr)
	}
	if code, _, _ := runCommandForTest(t, "policy", "check", "--policy", filepath.Join(dir, "missing.yaml")); code != 1 {
		t.Fatalf("missing file exit = %d, want 1", code)
	}
	if code, _, _ := runCommandForTest(t, "policy", "check"); code != 1 {
		t.Fatalf("no --policy exit = %d, want 1", code)
	}
}
