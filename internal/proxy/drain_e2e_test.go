package proxy

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDrainAuditsOnUpstreamClose verifies that when an upstream response never arrives
// (upstream crashes, closes stdout, or drops a response), the proxy still emits the
// buffered audits without committing card state.
func TestDrainAuditsOnUpstreamClose(t *testing.T) {
	binary := buildBinary(t)
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	// Generate Ed25519 keypair for signing.
	keygenOut, err := exec.Command(binary, "keygen").Output()
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	seedHex := envValue(t, string(keygenOut), "NOCKGUARD_AUDIT_ED25519_KEY")
	pubHex := envValue(t, string(keygenOut), "NOCKGUARD_AUDIT_ED25519_PUB")

	// Policy with Ed25519-signed audit and nockcc_nock_claim allowed.
	policyFile := filepath.Join(dir, "policy.yaml")
	policyContent := "agents:\n" +
		"  kit:\n" +
		"    allow:\n" +
		"      - \"nockcc_nock_claim\"\n" +
		"      - \"generic_tool_*\"\n" +
		"audit:\n" +
		"  enabled: true\n" +
		"  path: " + auditPath + "\n" +
		"  sign_ed25519_key_env: NOCKGUARD_AUDIT_ED25519_KEY\n"
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Mock upstream that reads request but never sends response (simulating crash).
	scriptDir := filepath.Join(dir, "scripts")
	if err := os.Mkdir(scriptDir, 0755); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(scriptDir, "no-response.sh")
	scriptContent := `#!/bin/bash
# Read all stdin but never send any response — simulate upstream crash
while IFS= read -r line; do
  :
done
# Exit without sending anything
exit 0
`
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		t.Fatal(err)
	}

	// Dispatch sequence: claim request that will never get a response.
	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_claim","arguments":{"id":12345}}}`,
	}
	proxyCmd := exec.Command(binary, "proxy", "--upstream", "bash", scriptPath, "--agent", "kit", "--policy", policyFile)
	proxyCmd.Stdin = strings.NewReader(strings.Join(requests, "\n") + "\n")
	proxyCmd.Env = append(os.Environ(), "NOCKGUARD_AUDIT_ED25519_KEY="+seedHex)
	out, err := proxyCmd.CombinedOutput()
	// Expect exit (stdin closed, upstream EOF, audits drained and emitted)
	_ = err
	_ = out

	// Verify the audit trail: claim's audit should be emitted despite no response.
	data, _ := os.ReadFile(auditPath)
	auditContent := string(data)

	if auditContent == "" {
		t.Fatalf("audit file is empty — drain failed to emit the claim audit")
	}

	lines := strings.Split(strings.TrimSpace(auditContent), "\n")
	if len(lines) == 0 {
		t.Fatalf("no audit entries — drain failed to emit the claim audit")
	}

	// Parse the audit entry to verify it's the claim with correct fields.
	type auditEntry struct {
		Tool   string `json:"tool"`
		NockID int    `json:"nock_id,omitempty"`
	}
	var entry auditEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("failed to parse audit line: %v\naudit content:\n%s", err, auditContent)
	}

	// Verify the claim audit was emitted.
	if entry.Tool != "nockcc_nock_claim" {
		t.Errorf("expected tool=nockcc_nock_claim, got tool=%s", entry.Tool)
	}

	// Verify the claim audit has the extracted NockID (not stamped from currentCard, since no response committed it).
	if entry.NockID != 12345 {
		t.Errorf("expected nock_id=12345 from request extraction, got nock_id=%d", entry.NockID)
	}

	// Verify the audit was signed correctly.
	verifyCmd := exec.Command(binary, "audit", "verify", "--ed25519-pub-env", "NOCKGUARD_AUDIT_ED25519_PUB", "--audit", auditPath)
	verifyCmd.Env = append(os.Environ(), "NOCKGUARD_AUDIT_ED25519_PUB="+pubHex)
	verifyOut, err := verifyCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify failed: %v\n%s", err, verifyOut)
	}
}
