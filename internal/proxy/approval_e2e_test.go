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

func TestApprovalGateAbsentByDefault(t *testing.T) {
	// No NOCKGUARD_APPROVAL_TEST and no real approver wired -> approver is nil, so
	// require_approval is present but un-enforced and the call passes (Phase 1-4
	// behavior preserved; the gate is strictly opt-in on having an approver).
	byID := runProxyEnv(t, approvalPolicy, approvalRequests())

	if byID[1]["error"] != nil {
		t.Errorf("with no approver wired, the call should pass through, got error: %v", byID[1]["error"])
	}
}
