package policy

import "testing"

// Phase 5 — interactive approval gates. RequiresApproval reports whether a
// (agent, tool) pair matches an approval-required pattern. It is an OPT-IN third
// gate, independent of allow/deny: a tool can be allowed by policy AND still
// require a human nod before it runs. Absence of any require_approval rule means
// no approval gate (Phase 1-4 behavior preserved).
func TestRequiresApproval(t *testing.T) {
	path := writePolicy(t, `
agents:
  kit:
    allow:
      - "nockcc_*"
    require_approval:
      - "nockcc_kill_switch_set"
      - "nockcc_spend_*"
  default:
    require_approval:
      - "*delete*"
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		agent, tool string
		want        bool
	}{
		{"exact match needs approval", "kit", "nockcc_kill_switch_set", true},
		{"wildcard match needs approval", "kit", "nockcc_spend_add", true},
		{"allowed tool, no approval rule", "kit", "nockcc_nock_list", false},
		{"unknown agent falls back to default rule", "wren", "fs_delete_file", true},
		{"default agent, no match", "wren", "nockcc_nock_get", false},
	}
	for _, tt := range tests {
		if got := eng.RequiresApproval(tt.agent, tt.tool); got != tt.want {
			t.Errorf("%s: RequiresApproval(%q, %q) = %v, want %v", tt.name, tt.agent, tt.tool, got, tt.want)
		}
	}
}

func TestRequiresApprovalNoneConfigured(t *testing.T) {
	path := writePolicy(t, `
agents:
  beck:
    allow:
      - "*"
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if eng.RequiresApproval("beck", "anything") {
		t.Error("RequiresApproval should be false when no require_approval is configured")
	}
	// Unknown agent, no default policy -> no approval gate.
	if eng.RequiresApproval("ghost", "anything") {
		t.Error("RequiresApproval should be false for unknown agent with no default policy")
	}
}
