package proxy

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runProxyEnv is runProxy with extra environment for the proxy subprocess —
// used to drive the Phase 5 approval test seam (NOCKGUARD_APPROVAL_TEST).
func runProxyEnv(t *testing.T, policyContent string, requests []string, env ...string) map[float64]map[string]interface{} {
	t.Helper()
	mockServer := writeMockServer(t)
	binary := buildBinary(t)

	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binary, "proxy", "--upstream", mockServer, "--agent", "kit", "--policy", policyFile)
	cmd.Stdin = strings.NewReader(strings.Join(requests, "\n") + "\n")
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("proxy exited with error: %v\nstderr: %s", err, string(out))
	}

	byID := map[float64]map[string]interface{}{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if id, ok := m["id"].(float64); ok {
			byID[id] = m
		}
	}
	return byID
}

const approvalPolicy = `agents:
  kit:
    allow:
      - "nockcc_*"
    ask:
      - "nockcc_kill_switch_set"
`

const legacyApprovalPolicy = `agents:
  kit:
    allow:
      - "nockcc_*"
    require_approval:
      - "nockcc_kill_switch_set"
`

func approvalRequests() []string {
	return []string{
		// requires approval
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_kill_switch_set"}}`,
		// allowed, no approval rule -> approver never consulted
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`,
	}
}

func TestApprovalGateDenied(t *testing.T) {
	byID := runProxyEnv(t, approvalPolicy, approvalRequests(), "NOCKGUARD_APPROVAL_TEST=deny")

	if msg := errorMessage(t, byID[1]); !strings.Contains(msg, "denied by approval gate") {
		t.Errorf("call 1 should be HELD then denied, got message: %q", msg)
	}
	if byID[2]["error"] != nil {
		t.Errorf("call 2 (no approval rule) must pass regardless of the gate, got error: %v", byID[2]["error"])
	}
}

func TestApprovalGateGranted(t *testing.T) {
	byID := runProxyEnv(t, approvalPolicy, approvalRequests(), "NOCKGUARD_APPROVAL_TEST=approve")

	if byID[1]["error"] != nil {
		t.Errorf("call 1 should be HELD then approved and forwarded, got error: %v", byID[1]["error"])
	}
	if byID[2]["error"] != nil {
		t.Errorf("call 2 should pass, got error: %v", byID[2]["error"])
	}
}

func TestAskGateFailsClosedWithoutApprover(t *testing.T) {
	byID := runProxyEnv(t, approvalPolicy, approvalRequests())

	if msg := errorMessage(t, byID[1]); !strings.Contains(msg, "denied by approval gate") {
		t.Errorf("with no approver wired, ask call should fail closed, got message: %q", msg)
	}
	if byID[2]["error"] != nil {
		t.Errorf("call 2 (no ask rule) should pass, got error: %v", byID[2]["error"])
	}
}

func TestLegacyApprovalGateAbsentByDefault(t *testing.T) {
	// No NOCKGUARD_APPROVAL_TEST and no real approver wired -> approver is nil, so
	// legacy require_approval is present but un-enforced and the call passes
	// (Phase 1-5 behavior preserved for existing policy files).
	byID := runProxyEnv(t, legacyApprovalPolicy, approvalRequests())

	if byID[1]["error"] != nil {
		t.Errorf("with no approver wired, legacy require_approval should pass through, got error: %v", byID[1]["error"])
	}
}

func TestLegacyRequireApprovalStillGatesWithoutHidingFromList(t *testing.T) {
	byID := runProxyEnv(t, legacyApprovalPolicy, []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nockcc_kill_switch_set"}}`,
	}, "NOCKGUARD_APPROVAL_TEST=deny")

	result := byID[1]["result"].(map[string]interface{})
	tools := result["tools"].([]interface{})
	found := false
	for _, tool := range tools {
		if tool.(map[string]interface{})["name"] == "nockcc_kill_switch_set" {
			found = true
		}
	}
	if !found {
		t.Fatal("legacy require_approval tool should remain visible in tools/list")
	}
	if msg := errorMessage(t, byID[2]); !strings.Contains(msg, "denied by approval gate") {
		t.Errorf("legacy require_approval call should still be held then denied, got message: %q", msg)
	}
}

func TestAskVerdictAppliesWithheldWritesOnlyOnApprove(t *testing.T) {
	for _, tc := range []struct {
		name           string
		approval       string
		wantCallError  bool
		wantStateWrite bool
	}{
		{"approved applies withheld write", "approve", false, true},
		{"denied drops withheld write", "deny", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			auditPath := filepath.Join(dir, "audit.jsonl")
			policyContent := `audit:
  enabled: true
  path: ` + auditPath + `
` + approvalPolicy

			byID := runProxyEnv(t, policyContent, []string{
				`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_kill_switch_set"}}`,
			}, "NOCKGUARD_APPROVAL_TEST="+tc.approval)

			if gotError := byID[1]["error"] != nil; gotError != tc.wantCallError {
				t.Fatalf("call error = %v, want %v: %v", gotError, tc.wantCallError, byID[1])
			}

			lines := readAuditFile(t, auditPath)
			foundStateWrite := false
			for _, ev := range lines {
				if ev["decision"] == "state-write" && ev["reason"] == `approval-state approved for ask-rule "nockcc_kill_switch_set"` {
					foundStateWrite = true
				}
			}
			if foundStateWrite != tc.wantStateWrite {
				t.Errorf("state-write audit present = %v, want %v; audit=%v", foundStateWrite, tc.wantStateWrite, lines)
			}
		})
	}
}

func TestFailModeAskParksUnextractableToolName(t *testing.T) {
	policyContent := `agents:
  kit:
    allow:
      - "nockcc_*"
    fail_mode: ask
`
	request := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"x":1}}}`,
	}

	denied := runProxyEnv(t, policyContent, request, "NOCKGUARD_APPROVAL_TEST=deny")
	if msg := errorMessage(t, denied[1]); !strings.Contains(msg, "tool name could not be extracted") {
		t.Fatalf("fail_mode ask denied should reject unextractable name, got %q", msg)
	}

	approved := runProxyEnv(t, policyContent, request, "NOCKGUARD_APPROVAL_TEST=approve")
	if approved[1]["error"] != nil {
		t.Fatalf("fail_mode ask approved should forward the canonical call, got error: %v", approved[1]["error"])
	}
}
