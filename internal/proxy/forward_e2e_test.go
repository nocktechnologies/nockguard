package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestForwardsEnforcementToOpsLogEndToEnd(t *testing.T) {
	var mu sync.Mutex
	var posts []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var b map[string]any
		_ = json.Unmarshal(raw, &b)
		mu.Lock()
		posts = append(posts, b)
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	mockServer := writeMockServer(t)
	binary := buildBinary(t)
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	policyContent := `audit:
  enabled: true
  path: ` + filepath.Join(dir, "audit.jsonl") + `
  forward:
    enabled: true
    url: ` + srv.URL + `
    api_key_env: NG_FWD_KEY
agents:
  kit:
    allow:
      - "nockcc_nock_*"
    deny:
      - "nockcc_kill_switch_set"
`
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatal(err)
	}

	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`,       // allow — not forwarded
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nockcc_kill_switch_set"}}`, // deny — forwarded
	}
	cmd := exec.Command(binary, "proxy", "--upstream", mockServer, "--agent", "kit", "--policy", policyFile)
	cmd.Env = append(os.Environ(), "NG_FWD_KEY=fwd-secret")
	cmd.Stdin = strings.NewReader(strings.Join(requests, "\n") + "\n")
	if out, err := cmd.Output(); err != nil {
		t.Fatalf("proxy error: %v\n%s", err, out)
	}
	// The proxy drains the forwarder on exit (defer Stop), so by the time
	// cmd.Output() returns the POST has been delivered.

	mu.Lock()
	defer mu.Unlock()
	if len(posts) != 1 {
		t.Fatalf("expected exactly 1 forwarded enforcement event (deny only), got %d: %v", len(posts), posts)
	}
	ev := posts[0]
	if ev["event_type"] != "other" || ev["severity"] != "warn" {
		t.Errorf("forwarded event_type/severity wrong: %v", ev)
	}
	blob, _ := ev["data_blob"].(map[string]any)
	if blob["decision"] != "deny" || blob["tool"] != "nockcc_kill_switch_set" || blob["source"] != "nockguard" {
		t.Errorf("forwarded data_blob wrong: %v", blob)
	}
}
