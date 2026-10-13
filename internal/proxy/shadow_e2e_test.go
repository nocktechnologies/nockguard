package proxy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestShadowWouldDenyAuditsWithoutBlockingEndToEnd(t *testing.T) {
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
    mode: allow
    shadow:
      - "nockcc_nock_*"
`
	if err := os.WriteFile(policyFile, []byte(policyContent), 0o644); err != nil {
		t.Fatal(err)
	}

	request := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_spend_summary"}}`
	cmd := exec.Command(binary, "proxy", "--upstream", mockServer, "--agent", "kit", "--policy", policyFile)
	cmd.Stdin = strings.NewReader(request + "\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("proxy error: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), `"result"`) {
		t.Fatalf("shadow miss should still reach upstream and return a result, got:\n%s", out)
	}

	lines := readAuditFile(t, auditPath)
	if len(lines) != 3 {
		t.Fatalf("expected dispatch, would-deny and live allow records, got %d: %v", len(lines), lines)
	}
	if lines[0]["decision"] != "dispatch" || lines[1]["decision"] != "would-deny" {
		t.Fatalf("first two audit decisions = %q, %q, want dispatch and would-deny; all=%v", lines[0]["decision"], lines[1]["decision"], lines)
	}
	if lines[2]["decision"] != "allow" {
		t.Fatalf("third audit decision = %q, want allow; all=%v", lines[2]["decision"], lines)
	}
	if !strings.Contains(lines[1]["reason"], "would-deny shadow") {
		t.Fatalf("would-deny reason should name shadow basis, got %q", lines[1]["reason"])
	}
}
