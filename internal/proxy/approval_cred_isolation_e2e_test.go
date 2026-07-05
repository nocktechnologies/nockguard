package proxy

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The human-approval gate only holds if the policed agent CANNOT read the
// dedicated Telegram approval bot's credentials. The proxy spawns the upstream
// MCP server (the agent) as a child; if that child inherited
// NOCKGUARD_APPROVAL_BOT_TOKEN / NOCKGUARD_APPROVAL_CHAT_ID it could read them
// from its own environment and drive the Telegram approve/callback APIs to
// SELF-APPROVE a human-gated call — silently defeating the very gate meant to
// keep a human in the loop (N8588).
//
// This mirrors TestUpstreamChildCannotReadSigningSeed for the approval creds:
// the approval bot token + chat id MUST be stripped from the upstream child's
// environment, while every unrelated variable is inherited unchanged. The
// approver itself runs in the PROXY process, so stripping the child's copy does
// not disable the gate.
func TestUpstreamChildCannotReadApprovalCreds(t *testing.T) {
	binary := buildBinary(t)
	dir := t.TempDir()

	// Mock MCP server that echoes the approval creds + an unrelated passthrough
	// var straight back in its tool-call result.
	mock := filepath.Join(dir, "echo-env.sh")
	script := `#!/bin/bash
while IFS= read -r line; do
  method=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin).get('method',''))" 2>/dev/null)
  id=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
  if [ "$method" = "tools/call" ]; then
    echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"token\":\"${NOCKGUARD_APPROVAL_BOT_TOKEN}\",\"chat\":\"${NOCKGUARD_APPROVAL_CHAT_ID}\",\"passthrough\":\"${NOCKGUARD_PASSTHROUGH}\"}}"
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
		"      - \"nockcc_*\"\n"
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatal(err)
	}

	req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nockcc_nock_list"}}`
	cmd := exec.Command(binary, "proxy", "--upstream", "bash "+mock, "--agent", "kit", "--policy", policyFile)
	cmd.Stdin = strings.NewReader(req + "\n")
	cmd.Env = append(os.Environ(),
		"NOCKGUARD_APPROVAL_BOT_TOKEN=secret-bot-token",
		"NOCKGUARD_APPROVAL_CHAT_ID=123456789",
		"NOCKGUARD_PASSTHROUGH=visible",
	)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("proxy run failed: %v\n%s", err, out)
	}

	var resp struct {
		Result struct {
			Token       string `json:"token"`
			Chat        string `json:"chat"`
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

	if resp.Result.Token != "" {
		t.Errorf("upstream child CAN read the approval bot token (approval gate self-approvable): token=%q", resp.Result.Token)
	}
	if resp.Result.Chat != "" {
		t.Errorf("upstream child CAN read the approval chat id: chat=%q", resp.Result.Chat)
	}
	if resp.Result.Passthrough != "visible" {
		t.Errorf("non-secret env var was not inherited by the child: passthrough=%q (want %q)", resp.Result.Passthrough, "visible")
	}
}
