package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func writePolicy(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAllowDenyExact(t *testing.T) {
	path := writePolicy(t, `
agents:
  kit:
    allow:
      - "nockcc_nock_list"
      - "nockcc_nock_get"
    deny:
      - "nockcc_kill_switch_set"
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		tool string
		want bool
	}{
		{"nockcc_nock_list", true},
		{"nockcc_nock_get", true},
		{"nockcc_kill_switch_set", false},
		{"nockcc_spend_summary", false}, // not in allow list
	}
	for _, tt := range tests {
		got := eng.Check("kit", tt.tool)
		if got != tt.want {
			t.Errorf("Check(kit, %q) = %v, want %v", tt.tool, got, tt.want)
		}
	}
}

func TestWildcardPatterns(t *testing.T) {
	path := writePolicy(t, `
agents:
  beck:
    allow:
      - "nockcc_nock_*"
      - "nockcc_ops_log_*"
    deny:
      - "nockcc_spend_*"
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		tool string
		want bool
	}{
		{"nockcc_nock_list", true},
		{"nockcc_nock_create", true},
		{"nockcc_ops_log_create", true},
		{"nockcc_spend_summary", false},
		{"nockcc_spend_add", false},
		{"nockcc_diary_list", false}, // not in allow
	}
	for _, tt := range tests {
		got := eng.Check("beck", tt.tool)
		if got != tt.want {
			t.Errorf("Check(beck, %q) = %v, want %v", tt.tool, got, tt.want)
		}
	}
}

func TestDefaultPolicy(t *testing.T) {
	path := writePolicy(t, `
agents:
  default:
    mode: allow
    deny:
      - "nockcc_kill_switch_set"
      - "nockcc_private_*"
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		agent string
		tool  string
		want  bool
	}{
		{"unknown_agent", "nockcc_nock_list", true},
		{"unknown_agent", "nockcc_kill_switch_set", false},
		{"unknown_agent", "nockcc_private_get", false},
		{"unknown_agent", "nockcc_private_list", false},
	}
	for _, tt := range tests {
		got := eng.Check(tt.agent, tt.tool)
		if got != tt.want {
			t.Errorf("Check(%q, %q) = %v, want %v", tt.agent, tt.tool, got, tt.want)
		}
	}
}

func TestDenyTakesPrecedenceOverAllow(t *testing.T) {
	path := writePolicy(t, `
agents:
  kit:
    allow:
      - "nockcc_*"
    deny:
      - "nockcc_kill_switch_set"
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if eng.Check("kit", "nockcc_kill_switch_set") {
		t.Error("deny should take precedence over wildcard allow")
	}
	if !eng.Check("kit", "nockcc_nock_list") {
		t.Error("nockcc_nock_list should be allowed by wildcard")
	}
}

func TestNoMatchingAgentNoDefault(t *testing.T) {
	path := writePolicy(t, `
agents:
  kit:
    allow:
      - "nockcc_nock_list"
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if !eng.Check("unknown", "anything") {
		t.Error("unknown agent with no default should be allowed")
	}
}

func TestFilterTools(t *testing.T) {
	path := writePolicy(t, `
agents:
  kit:
    allow:
      - "nockcc_nock_*"
    deny:
      - "nockcc_kill_switch_set"
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	tools := []string{"nockcc_nock_list", "nockcc_nock_get", "nockcc_kill_switch_set", "nockcc_spend_add"}
	got := eng.FilterTools("kit", tools)
	if len(got) != 2 || got[0] != "nockcc_nock_list" || got[1] != "nockcc_nock_get" {
		t.Errorf("FilterTools = %v, want [nockcc_nock_list nockcc_nock_get]", got)
	}
}

func TestDefaultDenyMode(t *testing.T) {
	path := writePolicy(t, `
agents:
  strict:
    mode: deny
    allow:
      - "nockcc_nock_list"
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if !eng.Check("strict", "nockcc_nock_list") {
		t.Error("explicitly allowed tool should pass in deny mode")
	}
	if eng.Check("strict", "nockcc_nock_create") {
		t.Error("unlisted tool should be blocked in deny mode")
	}
}
