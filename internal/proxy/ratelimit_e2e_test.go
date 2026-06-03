package proxy

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runProxy builds the binary, feeds it the given JSON-RPC request lines through
// the mock MCP server under the given policy, and returns the parsed responses
// keyed by id.
func runProxy(t *testing.T, policyContent string, requests []string) map[float64]map[string]interface{} {
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

func errorMessage(t *testing.T, resp map[string]interface{}) string {
	t.Helper()
	if resp == nil {
		t.Fatal("missing response")
	}
	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected error response, got %v", resp)
	}
	return errObj["message"].(string)
}

func TestRateLimitEndToEnd(t *testing.T) {
	policyContent := `agents:
  kit:
    allow:
      - "nockcc_nock_*"
    rate_limit:
      max_calls: 2
      window: 1m
`
	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`,
	}
	byID := runProxy(t, policyContent, requests)

	if byID[1]["error"] != nil {
		t.Errorf("call 1 should be allowed, got error: %v", byID[1]["error"])
	}
	if byID[2]["error"] != nil {
		t.Errorf("call 2 should be allowed, got error: %v", byID[2]["error"])
	}
	if msg := errorMessage(t, byID[3]); !strings.Contains(msg, "rate limit") {
		t.Errorf("call 3 should be rate-limited, got message: %q", msg)
	}
}

func TestSpendCapEndToEnd(t *testing.T) {
	policyContent := `agents:
  kit:
    allow:
      - "nockcc_nock_*"
    spend_cap:
      max_calls: 1
`
	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`,
	}
	byID := runProxy(t, policyContent, requests)

	if byID[1]["error"] != nil {
		t.Errorf("call 1 should be allowed, got error: %v", byID[1]["error"])
	}
	if msg := errorMessage(t, byID[2]); !strings.Contains(msg, "spend cap") {
		t.Errorf("call 2 should hit spend cap, got message: %q", msg)
	}
}

func TestDeniedCallsDoNotConsumeRateBudget(t *testing.T) {
	// A policy-denied tool returns an error before the limiter runs, so it must
	// not count against the rate budget: two allowed calls should still pass
	// even with a denied call interleaved.
	policyContent := `agents:
  kit:
    allow:
      - "nockcc_nock_*"
    deny:
      - "nockcc_kill_switch_set"
    rate_limit:
      max_calls: 2
      window: 1m
`
	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nockcc_kill_switch_set"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`,
	}
	byID := runProxy(t, policyContent, requests)

	if byID[1]["error"] != nil {
		t.Errorf("call 1 (allowed) should pass, got error: %v", byID[1]["error"])
	}
	if msg := errorMessage(t, byID[2]); !strings.Contains(msg, "denied") {
		t.Errorf("call 2 should be policy-denied, got: %q", msg)
	}
	if byID[3]["error"] != nil {
		t.Errorf("call 3 (allowed) should pass — denied call must not consume rate budget, got error: %v", byID[3]["error"])
	}
}
