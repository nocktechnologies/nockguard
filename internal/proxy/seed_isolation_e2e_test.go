package proxy

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The non-repudiation claim only holds if the policed agent CANNOT read the
// signing seed. The proxy spawns the upstream MCP server (the agent) as a child;
// if that child inherits NOCKGUARD_AUDIT_ED25519_KEY it can read it from its own
// environment and forge the entire audit trail — non-repudiable against an
// outside reader, worthless against the audited party.
//
// This drives the seed-isolation fix end to end: the configured signing env var
// MUST be stripped from the upstream child's environment, while every other
// variable is inherited unchanged.
func TestUpstreamChildCannotReadSigningSeed(t *testing.T) {
	binary := buildBinary(t)
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	// Mock MCP server that echoes two env vars straight back in its tool-call
	// result: the secret signing seed and an unrelated passthrough var.
	mock := filepath.Join(dir, "echo-env.sh")
	script := `#!/bin/bash
while IFS= read -r line; do
  method=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin).get('method',''))" 2>/dev/null)
  id=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
  if [ "$method" = "tools/call" ]; then
    echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"seed\":\"${NOCKGUARD_AUDIT_ED25519_KEY}\",\"passthrough\":\"${NOCKGUARD_PASSTHROUGH}\"}}"
  fi
done
`
	if err := os.WriteFile(mock, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	policyFile := filepath.Join(dir, "policy.yaml")
	policyContent := "agents:\n" +
		"  kit:\n" +
		"    allow:\n" +
		"      - \"nockcc_*\"\n" +
		"audit:\n" +
		"  enabled: true\n" +
		"  path: " + auditPath + "\n" +
		"  sign_ed25519_key_env: NOCKGUARD_AUDIT_ED25519_KEY\n"
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatal(err)
	}

	// A valid 32-byte (64 hex) Ed25519 seed so the proxy starts; the Auditor
	// parses it at startup, so the child never needs the variable.
	seed := strings.Repeat("ab", 32)

	req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`
	cmd := exec.Command(binary, "proxy", "--upstream", "bash "+mock, "--agent", "kit", "--policy", policyFile)
	cmd.Stdin = strings.NewReader(req + "\n")
	cmd.Env = append(os.Environ(),
		"NOCKGUARD_AUDIT_ED25519_KEY="+seed,
		"NOCKGUARD_PASSTHROUGH=visible",
	)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("proxy run failed: %v\n%s", err, out)
	}

	var resp struct {
		Result struct {
			Seed        string `json:"seed"`
			Passthrough string `json:"passthrough"`
		} `json:"result"`
	}
	var parsed bool
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		if err := json.Unmarshal([]byte(line), &resp); err == nil && resp.Result.Passthrough != "" {
			parsed = true
			break
		}
	}
	if !parsed {
		t.Fatalf("did not get the upstream echo response; output:\n%s", out)
	}

	if resp.Result.Seed != "" {
		t.Errorf("upstream child CAN read the signing seed (non-repudiation broken): seed=%q", resp.Result.Seed)
	}
	if resp.Result.Passthrough != "visible" {
		t.Errorf("non-secret env var was not inherited by the child: passthrough=%q (want %q)", resp.Result.Passthrough, "visible")
	}
}
