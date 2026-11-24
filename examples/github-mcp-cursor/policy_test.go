package githubmcpcursor

import (
	"encoding/json"
	"maps"
	"os"
	"slices"
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
			Type    string            `json:"type"`
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			Env     map[string]string `json:"env"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("mcp.json is not valid JSON: %v", err)
	}
	github := cfg.MCPServers["github"]
	if github.Type != "stdio" || github.Command != "<NOCKGUARD_PATH>" {
		t.Errorf("mcp.json github type/command = %q/%q, want stdio/<NOCKGUARD_PATH>", github.Type, github.Command)
	}
	wantArgs := []string{"proxy", "--upstream", "<DOCKER_PATH> run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN ghcr.io/github/github-mcp-server:v2.0.3", "--agent", "cursor", "--policy", "<POLICY_PATH>"}
	if !slices.Equal(github.Args, wantArgs) {
		t.Errorf("mcp.json github args = %q, want %q", github.Args, wantArgs)
	}
	// Cursor documents ${env:NAME} for environment interpolation, not the
	// plain ${NAME} the Claude Code example uses.
	wantEnv := map[string]string{"PATH": "<SHELL_PATH>", "GITHUB_PERSONAL_ACCESS_TOKEN": "${env:GITHUB_PERSONAL_ACCESS_TOKEN}"}
	if !maps.Equal(github.Env, wantEnv) {
		t.Errorf("mcp.json github env = %q, want %q", github.Env, wantEnv)
	}
}
