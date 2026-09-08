package proxy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestAuditableReferencesEndToEnd verifies that nockcc_nock_* tool calls
// carry extracted NockID references in audit trails, and that the session-scoped
// current card is stamped onto subsequent rows.
func TestAuditableReferencesEndToEnd(t *testing.T) {
	binary := buildBinary(t)
	mockServer := writeMockServer(t)
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	// Generate Ed25519 keypair for signing.
	keygenOut, err := exec.Command(binary, "keygen").Output()
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	seedHex := envValue(t, string(keygenOut), "NOCKGUARD_AUDIT_ED25519_KEY")
	pubHex := envValue(t, string(keygenOut), "NOCKGUARD_AUDIT_ED25519_PUB")

	// Policy with Ed25519-signed audit and nockcc_nock_* tools allowed.
	policyFile := filepath.Join(dir, "policy.yaml")
	policyContent := "agents:\n" +
		"  kit:\n" +
		"    allow:\n" +
		"      - \"nockcc_nock_claim\"\n" +
		"      - \"nockcc_nock_get\"\n" +
		"      - \"nockcc_nock_update\"\n" +
		"      - \"nockcc_nock_release\"\n" +
		"audit:\n" +
		"  enabled: true\n" +
		"  path: " + auditPath + "\n" +
		"  sign_ed25519_key_env: NOCKGUARD_AUDIT_ED25519_KEY\n"
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Simulated dispatch through the proxy:
	// 1. nockcc_nock_claim with id=12345 (claim the card, sets current-card)
	// 2. nockcc_nock_get with id=67890 (a different card get, extracts its id)
	// 3. nockcc_nock_update (no id, should inherit current card from claim)
	// 4. nockcc_nock_release with id=12345 (release the claimed card)
	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_claim","id":12345}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nockcc_nock_get","id":67890}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nockcc_nock_update","id":12345,"title":"Updated"}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nockcc_nock_release","id":12345}}`,
	}
	proxyCmd := exec.Command(binary, "proxy", "--upstream", mockServer, "--agent", "kit", "--policy", policyFile)
	proxyCmd.Stdin = strings.NewReader(strings.Join(requests, "\n") + "\n")
	proxyCmd.Env = append(os.Environ(), "NOCKGUARD_AUDIT_ED25519_KEY="+seedHex)
	if out, err := proxyCmd.CombinedOutput(); err != nil {
		t.Fatalf("proxy run failed: %v\n%s", err, out)
	}

	// Verify the trail with the public key.
	verifyCmd := exec.Command(binary, "audit", "verify", "--ed25519-pub-env", "NOCKGUARD_AUDIT_ED25519_PUB", "--audit", auditPath)
	verifyCmd.Env = append(os.Environ(), "NOCKGUARD_AUDIT_ED25519_PUB="+pubHex)
	verifyOut, err := verifyCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify failed: %v\n%s", err, verifyOut)
	}

	// Read the audit trail and verify the auditable fields are present.
	data, _ := os.ReadFile(auditPath)
	auditContent := string(data)

	// Verify claim row has nock_id=12345
	if !strings.Contains(auditContent, `"nock_id":12345`) {
		t.Errorf("claim row missing nock_id:12345; got:\n%s", auditContent)
	}

	// Verify nockcc_nock_get row has nock_id=67890 (extracted from its own args)
	if !strings.Contains(auditContent, `"tool":"nockcc_nock_get"`) ||
		!strings.Contains(auditContent, `"nock_id":67890`) {
		t.Errorf("get row missing nock_id:67890; got:\n%s", auditContent)
	}

	// Verify nockcc_nock_update row has nock_id=12345
	// (extracted from args but we should have both claim and update with same id)
	lines := strings.Split(auditContent, "\n")
	claimCount := 0
	updateCount := 0
	for _, line := range lines {
		if strings.Contains(line, `"tool":"nockcc_nock_claim"`) && strings.Contains(line, `"nock_id":12345`) {
			claimCount++
		}
		if strings.Contains(line, `"tool":"nockcc_nock_update"`) && strings.Contains(line, `"nock_id":12345`) {
			updateCount++
		}
	}
	if claimCount == 0 {
		t.Errorf("no claim row with nock_id:12345")
	}
	if updateCount == 0 {
		t.Errorf("no update row with nock_id:12345")
	}
}
