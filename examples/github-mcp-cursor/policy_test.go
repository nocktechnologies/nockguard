package githubmcpcursor

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/nocktechnologies/nockguard/internal/policy"
)

func TestPolicyVerdicts(t *testing.T) {
	engine, err := policy.Load("policy.yaml")
	if err != nil {
		t.Fatalf("load policy.yaml: %v", err)
	}
	for _, tc := range []struct {
		tool string
		want policy.Verdict
	}{
		// Denied by tool name, whatever the arguments, so a create with
		// private=false is denied too.
		{"create_repository", policy.Deny},
		{"fork_repository", policy.Deny},
		{"delete_repository", policy.Deny},
		// Negative controls: ordinary GitHub work stays allowed.
		{"create_pull_request", policy.Allow},
		{"list_pull_requests", policy.Allow},
	} {
		if got := engine.Evaluate("cursor", tc.tool); got.Verdict != tc.want {
			t.Errorf("%s: got %v (%s), want %v", tc.tool, got.Verdict, got.Reason, tc.want)
		}
	}
	// An agent name the policy does not list fails closed.
	if got := engine.Evaluate("codex", "list_pull_requests"); got.Verdict != policy.Deny {
		t.Errorf("unlisted agent: got %v (%s), want deny", got.Verdict, got.Reason)
	}
}

func TestMCPConfigWrapsGitHubServer(t *testing.T) {
	raw, err := os.ReadFile("mcp.json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		MCPServers map[string]struct {
			Type string            `json:"type"`
			Args []string          `json:"args"`
			Env  map[string]string `json:"env"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("mcp.json is not valid JSON: %v", err)
	}
	github := cfg.MCPServers["github"]
	if github.Type != "stdio" {
		t.Errorf("mcp.json github type = %q, want stdio", github.Type)
	}
	args := strings.Join(github.Args, " ")
	for _, want := range []string{"proxy --upstream", "ghcr.io/github/github-mcp-server:v2.0.3", "--agent cursor", "--policy"} {
		if !strings.Contains(args, want) {
			t.Errorf("mcp.json github args %q missing %q", args, want)
		}
	}
	// Cursor documents ${env:NAME} for environment interpolation, not the
	// plain ${NAME} the Claude Code example uses.
	if got := github.Env["GITHUB_PERSONAL_ACCESS_TOKEN"]; got != "${env:GITHUB_PERSONAL_ACCESS_TOKEN}" {
		t.Errorf("mcp.json github token env = %q, want ${env:GITHUB_PERSONAL_ACCESS_TOKEN}", got)
	}
}
