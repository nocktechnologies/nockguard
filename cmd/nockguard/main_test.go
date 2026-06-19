package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
