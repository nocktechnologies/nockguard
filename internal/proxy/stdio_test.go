package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestEndToEnd(t *testing.T) {
	mockServer := writeMockServer(t)
	policyFile := writePolicyFile(t)
	binary := buildBinary(t)

	cmd := exec.Command(binary, "proxy",
		"--upstream", mockServer,
		"--agent", "kit",
		"--policy", policyFile,
	)

	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nockcc_kill_switch_set"}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nockcc_spend_add"}}`,
	}, "\n")

	cmd.Stdin = strings.NewReader(input + "\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("proxy exited with error: %v\nstderr: %s", err, string(out))
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")

	var responses []map[string]interface{}
	for _, line := range lines {
		if line == "" {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Logf("non-JSON line: %s", line)
			continue
		}
		responses = append(responses, m)
	}

	if len(responses) < 4 {
		t.Fatalf("expected at least 4 responses, got %d: %v", len(responses), lines)
	}

	// Response to id=2 (tools/list) should have filtered tools
	for _, r := range responses {
		id, _ := r["id"].(float64)
		if id == 2 {
			result, ok := r["result"].(map[string]interface{})
			if !ok {
				t.Fatal("tools/list response missing result")
			}
			tools, ok := result["tools"].([]interface{})
			if !ok {
				t.Fatal("tools/list result missing tools array")
			}
			for _, tool := range tools {
				tm := tool.(map[string]interface{})
				name := tm["name"].(string)
				if name == "nockcc_kill_switch_set" || name == "nockcc_spend_add" {
					t.Errorf("tools/list should not include denied tool %q", name)
				}
			}
		}

		// Response to id=4 (kill_switch_set) should be an error from nockguard
		if id == 4 {
			if r["error"] == nil {
				t.Error("tools/call for denied tool should return error")
			}
			errObj := r["error"].(map[string]interface{})
			msg := errObj["message"].(string)
			if !strings.Contains(msg, "denied") {
				t.Errorf("error message should contain 'denied', got: %s", msg)
			}
		}

		// Response to id=5 (spend_add) should also be denied
		if id == 5 {
			if r["error"] == nil {
				t.Error("tools/call for spend_add should return error")
			}
		}

		// Response to id=3 (nock_list) should succeed
		if id == 3 {
			if r["error"] != nil {
				t.Error("tools/call for allowed tool should not return error")
			}
		}
	}
}

func writeMockServer(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "mock-mcp.sh")
	content := `#!/bin/bash
while IFS= read -r line; do
  id=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
  method=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin).get('method',''))" 2>/dev/null)

  if [ "$method" = "initialize" ]; then
    echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{\"tools\":{}}}}"
  elif [ "$method" = "tools/list" ]; then
    echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"tools\":[{\"name\":\"nockcc_nock_list\",\"description\":\"List nocks\"},{\"name\":\"nockcc_nock_get\",\"description\":\"Get nock\"},{\"name\":\"nockcc_kill_switch_set\",\"description\":\"Set kill switch\"},{\"name\":\"nockcc_spend_add\",\"description\":\"Add spend\"}]}}"
  elif [ "$method" = "tools/call" ]; then
    tool=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin).get('params',{}).get('name',''))" 2>/dev/null)
    echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"called $tool\"}]}}"
  fi
done
`
	if err := os.WriteFile(script, []byte(content), 0755); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("bash %s", script)
}

func writePolicyFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	content := `agents:
  kit:
    allow:
      - "nockcc_nock_*"
    deny:
      - "nockcc_kill_switch_set"
      - "nockcc_spend_*"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func buildBinary(t *testing.T) string {
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

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}
