package proxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrustScoringScalesRateLimitEndToEnd(t *testing.T) {
	dir := t.TempDir()
	trustPath := filepath.Join(dir, "kit.json")
	policyContent := `agents:
  kit:
    allow:
      - "nockcc_nock_*"
    deny:
      - "nockcc_kill_switch_set"
    rate_limit:
      max_calls: 10
      window: 1m
    trust:
      enabled: true
      path: ` + trustPath + `
`
	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_kill_switch_set"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nockcc_kill_switch_set"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`,
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`,
	}
	byID := runProxy(t, policyContent, requests)

	for _, id := range []float64{1, 2} {
		if msg := errorMessage(t, byID[id]); !strings.Contains(msg, "denied") {
			t.Fatalf("id %.0f should be denied, got %q", id, msg)
		}
	}
	for _, id := range []float64{3, 4, 5, 6, 7} {
		if byID[id]["error"] != nil {
			t.Fatalf("id %.0f should pass before reduced cap is exhausted, got %v", id, byID[id]["error"])
		}
	}
	if msg := errorMessage(t, byID[8]); !strings.Contains(msg, "rate limit") {
		t.Fatalf("id 8 should hit trust-reduced rate cap, got %q", msg)
	}
	if _, err := os.Stat(trustPath); err != nil {
		t.Fatalf("trust score should be persisted at %s: %v", trustPath, err)
	}
}
