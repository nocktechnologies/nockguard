package githubmcpcodex

import (
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
		if got := engine.Evaluate("codex", tc.tool); got.Verdict != tc.want {
			t.Errorf("%s: got %v (%s), want %v", tc.tool, got.Verdict, got.Reason, tc.want)
		}
	}
	// An agent name the policy does not list fails closed.
	if got := engine.Evaluate("claude-code", "list_pull_requests"); got.Verdict != policy.Deny {
		t.Errorf("unlisted agent: got %v (%s), want deny", got.Verdict, got.Reason)
	}
}

// The repo has no TOML parser, so this checks the
// [mcp_servers.github] table as text, up to the next table.
func TestConfigWrapsGitHubServer(t *testing.T) {
	raw, err := os.ReadFile("config.toml")
	if err != nil {
		t.Fatal(err)
	}
	_, table, ok := strings.Cut(string(raw), "[mcp_servers.github]\n")
	if !ok {
		t.Fatal("config.toml has no [mcp_servers.github] table")
	}
	table, _, _ = strings.Cut(table, "\n[")
	for _, want := range []string{
		`command = "<NOCKGUARD_PATH>"`,
		`"proxy", "--upstream"`,
		"ghcr.io/github/github-mcp-server:v2.0.3",
		`"--agent", "codex"`,
		`"--policy"`,
		`env_vars = ["GITHUB_PERSONAL_ACCESS_TOKEN"]`,
	} {
		if !strings.Contains(table, want) {
			t.Errorf("[mcp_servers.github] missing %s", want)
		}
	}
}
