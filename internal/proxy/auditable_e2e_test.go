package proxy

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestAuditableReferencesEndToEnd verifies that nockcc_nock_* tool calls
// carry extracted NockID references in audit trails, and that the session-scoped
// current card is stamped onto subsequent rows that don't extract their own ID.
//
// This test exercises both the stamping path (generic tools getting the current card)
// and the clearing path (calls after release don't get stamped).
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

	// Policy with Ed25519-signed audit, nockcc_nock_* tools, and generic tools allowed.
	policyFile := filepath.Join(dir, "policy.yaml")
	policyContent := "agents:\n" +
		"  kit:\n" +
		"    allow:\n" +
		"      - \"nockcc_nock_claim\"\n" +
		"      - \"nockcc_nock_get\"\n" +
		"      - \"nockcc_nock_release\"\n" +
		"      - \"generic_*\"\n" +
		"audit:\n" +
		"  enabled: true\n" +
		"  path: " + auditPath + "\n" +
		"  sign_ed25519_key_env: NOCKGUARD_AUDIT_ED25519_KEY\n"
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Dispatch sequence that exercises both stamping and clearing.
	// Use protocol-valid MCP shapes: {"name": "...", "arguments": {...}}
	// 1. claim id=12345 (sets currentCard=12345)
	// 2. generic_tool_a with no id → gets stamped with currentCard=12345 (STAMPING PATH)
	// 3. get id=67890 (explicit id extraction → no stamp, own id)
	// 4. generic_tool_b with no id → still gets stamped with currentCard=12345
	// 5. release id=12345 (clears currentCard)
	// 6. generic_tool_c with no id → should NOT get stamped (CLEARING PATH)
	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_claim","arguments":{"id":12345}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"generic_tool_a","arguments":{"some_param":"value"}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nockcc_nock_get","arguments":{"id":67890}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"generic_tool_b","arguments":{"other_param":"data"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nockcc_nock_release","arguments":{"id":12345}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"generic_tool_c","arguments":{"final_param":"test"}}}`,
	}
	proxyCmd := exec.Command(binary, "proxy", "--upstream", mockServer, "--agent", "kit", "--policy", policyFile)
	proxyCmd.Stdin = strings.NewReader(strings.Join(requests, "\n") + "\n")
	proxyCmd.Env = append(os.Environ(), "NOCKGUARD_AUDIT_ED25519_KEY="+seedHex)
	out, err := proxyCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("proxy run failed: %v\n%s", err, out)
	}

	// Verify the trail with the public key.
	verifyCmd := exec.Command(binary, "audit", "verify", "--ed25519-pub-env", "NOCKGUARD_AUDIT_ED25519_PUB", "--audit", auditPath)
	verifyCmd.Env = append(os.Environ(), "NOCKGUARD_AUDIT_ED25519_PUB="+pubHex)
	verifyOut, err := verifyCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify failed: %v\n%s", err, verifyOut)
	}

	// Read and parse the audit trail.
	data, _ := os.ReadFile(auditPath)
	auditContent := string(data)

	lines := strings.Split(strings.TrimSpace(auditContent), "\n")

	// Parse each line as JSON to access individual fields.
	type auditEntry struct {
		Tool   string `json:"tool"`
		NockID int    `json:"nock_id,omitempty"`
	}
	entries := make([]auditEntry, 0)
	for _, line := range lines {
		if line == "" {
			continue
		}
		var entry auditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("failed to parse audit line: %v\naudit content:\n%s", err, auditContent)
		}
		entries = append(entries, entry)
	}

	if len(entries) != 6 {
		t.Errorf("expected 6 audit entries, got %d\naudit content:\n%s", len(entries), auditContent)
		return
	}

	// Verify claim row: tool=nockcc_nock_claim, nock_id=12345
	if entries[0].Tool != "nockcc_nock_claim" || entries[0].NockID != 12345 {
		t.Errorf("entry 0: expected nockcc_nock_claim with nock_id=12345, got tool=%s nock_id=%d",
			entries[0].Tool, entries[0].NockID)
	}

	// Verify generic_tool_a row: should be stamped with currentCard=12345 (STAMPING PATH)
	// This row does NOT have an id in its arguments, so it MUST get the current card.
	// If this fails, the stamping logic is broken.
	if entries[1].Tool != "generic_tool_a" || entries[1].NockID != 12345 {
		t.Errorf("entry 1 (STAMPING PATH): expected generic_tool_a with stamped nock_id=12345, got tool=%s nock_id=%d",
			entries[1].Tool, entries[1].NockID)
	}

	// Verify nockcc_nock_get row: tool=nockcc_nock_get, nock_id=67890 (explicit extraction)
	if entries[2].Tool != "nockcc_nock_get" || entries[2].NockID != 67890 {
		t.Errorf("entry 2: expected nockcc_nock_get with nock_id=67890, got tool=%s nock_id=%d",
			entries[2].Tool, entries[2].NockID)
	}

	// Verify generic_tool_b row: should be stamped with currentCard=12345 (still in session)
	if entries[3].Tool != "generic_tool_b" || entries[3].NockID != 12345 {
		t.Errorf("entry 3: expected generic_tool_b with stamped nock_id=12345, got tool=%s nock_id=%d",
			entries[3].Tool, entries[3].NockID)
	}

	// Verify release row: tool=nockcc_nock_release, nock_id=12345
	if entries[4].Tool != "nockcc_nock_release" || entries[4].NockID != 12345 {
		t.Errorf("entry 4: expected nockcc_nock_release with nock_id=12345, got tool=%s nock_id=%d",
			entries[4].Tool, entries[4].NockID)
	}

	// Verify generic_tool_c row: should NOT be stamped (CLEARING PATH)
	// After release, currentCard should be 0, so this generic tool should have no nock_id.
	// If this fails, the clearing logic is broken.
	if entries[5].Tool != "generic_tool_c" || entries[5].NockID != 0 {
		t.Errorf("entry 5 (CLEARING PATH): expected generic_tool_c with NO stamp (nock_id=0), got tool=%s nock_id=%d",
			entries[5].Tool, entries[5].NockID)
	}
}
