package githubmcpclaudecode

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
		if got := engine.Evaluate("claude-code", tc.tool); got.Verdict != tc.want {
			t.Errorf("%s: got %v (%s), want %v", tc.tool, got.Verdict, got.Reason, tc.want)
		}
	}
}

func TestMCPConfigWrapsGitHubServer(t *testing.T) {
	raw, err := os.ReadFile(".mcp.json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		MCPServers map[string]struct {
			Args []string `json:"args"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf(".mcp.json is not valid JSON: %v", err)
	}
	args := strings.Join(cfg.MCPServers["github"].Args, " ")
	for _, want := range []string{"proxy --upstream", "ghcr.io/github/github-mcp-server:v2.0.3", "--agent claude-code", "--policy"} {
		if !strings.Contains(args, want) {
			t.Errorf(".mcp.json github args %q missing %q", args, want)
		}
	}
}
