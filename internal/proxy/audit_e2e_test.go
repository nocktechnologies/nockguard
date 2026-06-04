package proxy

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func readAuditFile(t *testing.T, path string) []map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit file %s: %v", path, err)
	}
	defer f.Close()
	var out []map[string]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var m map[string]string
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("audit line not valid JSON: %v\n%s", err, sc.Text())
		}
		out = append(out, m)
	}
	return out
}

func TestAuditTrailRecordsDecisions(t *testing.T) {
	mockServer := writeMockServer(t)
	binary := buildBinary(t)

	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	policyFile := filepath.Join(dir, "policy.yaml")
	policyContent := `audit:
  enabled: true
  path: ` + auditPath + `
agents:
  kit:
    allow:
      - "nockcc_nock_*"
    deny:
      - "nockcc_kill_switch_set"
    rate_limit:
      max_calls: 2
      window: 1m
`
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatal(err)
	}

	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nockcc_kill_switch_set"}}`,
	}
	cmd := exec.Command(binary, "proxy", "--upstream", mockServer, "--agent", "kit", "--policy", policyFile)
	cmd.Stdin = strings.NewReader(strings.Join(requests, "\n") + "\n")
	if out, err := cmd.Output(); err != nil {
		t.Fatalf("proxy error: %v\n%s", err, out)
	}

	lines := readAuditFile(t, auditPath)
	if len(lines) != 4 {
		t.Fatalf("expected 4 audit records, got %d: %v", len(lines), lines)
	}

	// Every record carries the audited shape.
	for i, ev := range lines {
		if ev["agent"] != "kit" || ev["tool"] == "" || ev["decision"] == "" || ev["ts"] == "" {
			t.Errorf("record %d missing required fields: %v", i, ev)
		}
		// Raw tool parameters must never be written to the audit trail.
		if _, leaked := ev["params"]; leaked {
			t.Errorf("record %d leaked params into audit trail: %v", i, ev)
		}
	}

	decisions := []string{lines[0]["decision"], lines[1]["decision"], lines[2]["decision"], lines[3]["decision"]}
	want := []string{"allow", "allow", "ratelimit", "deny"}
	for i := range want {
		if decisions[i] != want[i] {
			t.Errorf("record %d decision = %q, want %q (all: %v)", i, decisions[i], want[i], decisions)
		}
	}
}
