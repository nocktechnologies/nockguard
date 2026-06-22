package policy

import (
	"os"
	"path/filepath"
	"strings"
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

	// Fail CLOSED: an agent with no named policy and no "default" must be denied
	// every tool — a silent allow-everything would contradict "default-deny".
	if eng.Check("unknown", "anything") {
		t.Error("unknown agent with no default should be DENIED (fail closed)")
	}
	if eng.HasPolicyFor("unknown") {
		t.Error("HasPolicyFor should report false for an unconfigured agent")
	}
	if !eng.HasPolicyFor("kit") {
		t.Error("HasPolicyFor should report true for a named agent")
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

// TestEvaluateProvenance verifies that Evaluate returns not just the verdict but
// the BASIS for it — naming the matched rule or the absence of one — across every
// decision path, including deny-beats-allow precedence. This is the data the
// audit trail records so a denial is explainable rather than an opaque "policy".
func TestEvaluateProvenance(t *testing.T) {
	path := writePolicy(t, `
agents:
  kit:
    allow:
      - "nockcc_nock_*"
    deny:
      - "nockcc_kill_switch_set"
      - "*delete*"
  locked:
    mode: deny
  permissive: {}
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		agent, tool string
		wantAllowed bool
		wantReason  string
	}{
		{"allow-match", "kit", "nockcc_nock_list", true, `allow-rule "nockcc_nock_*"`},
		{"explicit-deny", "kit", "nockcc_kill_switch_set", false, `deny-rule "nockcc_kill_switch_set"`},
		{"deny-beats-allow", "kit", "nockcc_nock_delete", false, `deny-rule "*delete*"`},
		{"no-allow-match", "kit", "nockcc_spend_summary", false, "no allow-rule matched"},
		{"mode-deny", "locked", "anything", false, `mode "deny", no allow list`},
		{"default-deny", "permissive", "anything", false, "default-deny (no allow list)"},
		{"no-policy-fail-closed", "ghost", "anything", false, "no policy for agent (fail-closed)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := eng.Evaluate(tt.agent, tt.tool)
			if dec.Allowed() != tt.wantAllowed {
				t.Errorf("Evaluate(%q, %q).Allowed() = %v, want %v", tt.agent, tt.tool, dec.Allowed(), tt.wantAllowed)
			}
			if dec.Reason != tt.wantReason {
				t.Errorf("Evaluate(%q, %q).Reason = %q, want %q", tt.agent, tt.tool, dec.Reason, tt.wantReason)
			}
			// Check must never disagree with Evaluate's verdict — it delegates.
			if got := eng.Check(tt.agent, tt.tool); got != dec.Allowed() {
				t.Errorf("Check(%q, %q) = %v but Evaluate.Allowed() = %v — verdict drift", tt.agent, tt.tool, got, dec.Allowed())
			}
		})
	}
}

func TestEvaluateTristateVerdict(t *testing.T) {
	path := writePolicy(t, `
agents:
  kit:
    allow:
      - "nockcc_*"
    deny:
      - "nockcc_kill_switch_set"
    ask:
      - "nockcc_spend_*"
  permissive:
    mode: allow
    ask:
      - "shell_*"
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name          string
		agent, tool   string
		wantVerdict   Verdict
		wantAllowed   bool
		wantWithheld  bool
		reasonSnippet string
	}{
		{"deny short-circuits ask/allow", "kit", "nockcc_kill_switch_set", Deny, false, false, `deny-rule "nockcc_kill_switch_set"`},
		{"ask after deny before allow", "kit", "nockcc_spend_add", Ask, false, true, `ask-rule "nockcc_spend_*"`},
		{"allow still works", "kit", "nockcc_nock_list", Allow, true, false, `allow-rule "nockcc_*"`},
		{"ask works without allow list", "permissive", "shell_exec", Ask, false, true, `ask-rule "shell_*"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := eng.Evaluate(tt.agent, tt.tool)
			if dec.Verdict != tt.wantVerdict {
				t.Fatalf("Verdict = %v, want %v", dec.Verdict, tt.wantVerdict)
			}
			if dec.Allowed() != tt.wantAllowed {
				t.Errorf("Allowed() = %v, want %v", dec.Allowed(), tt.wantAllowed)
			}
			if (len(dec.Withheld) > 0) != tt.wantWithheld {
				t.Errorf("len(Withheld) = %d, want withheld=%v", len(dec.Withheld), tt.wantWithheld)
			}
			if !strings.Contains(dec.Reason, tt.reasonSnippet) {
				t.Errorf("Reason = %q, want to contain %q", dec.Reason, tt.reasonSnippet)
			}
		})
	}
}

func TestEvaluateShadowMissRecordsWouldDenyBasisWithoutDenying(t *testing.T) {
	path := writePolicy(t, `
agents:
  kit:
    mode: allow
    deny:
      - "nockcc_kill_switch_set"
    shadow:
      - "nockcc_nock_*"
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	allowed := eng.Evaluate("kit", "nockcc_nock_list")
	if !allowed.Allowed() {
		t.Fatalf("shadow-listed tool should keep live allow verdict, got %+v", allowed)
	}
	if strings.Contains(allowed.Reason, "would-deny") {
		t.Fatalf("shadow-listed tool should not add would-deny basis: %q", allowed.Reason)
	}

	miss := eng.Evaluate("kit", "nockcc_spend_summary")
	if !miss.Allowed() {
		t.Fatalf("shadow miss in observe mode must not deny live call, got %+v", miss)
	}
	if !strings.Contains(miss.Reason, "would-deny") || !strings.Contains(miss.Reason, "shadow") {
		t.Fatalf("shadow miss should be recorded in reason, got %q", miss.Reason)
	}

	denied := eng.Evaluate("kit", "nockcc_kill_switch_set")
	if denied.Allowed() {
		t.Fatalf("explicit deny must still deny, got %+v", denied)
	}
	if strings.Contains(denied.Reason, "would-deny") {
		t.Fatalf("explicit deny should not be rewritten as shadow miss: %q", denied.Reason)
	}
}

// TestEmptyAllowListDefaultsDeny proves N8182 finding #1: a named agent with an
// empty or absent allow list and no explicit mode must DENY (fail-closed) rather
// than allow everything. Previously the empty-allow branch fell through to
// "default-allow", contradicting NockGuard's documented default-deny posture.
func TestEmptyAllowListDefaultsDeny(t *testing.T) {
	tests := []struct {
		name   string
		yaml   string
		agent  string
		reason string
	}{
		{
			name: "empty allow list",
			yaml: `
agents:
  restrictive:
    allow: []
`,
			agent:  "restrictive",
			reason: "default-deny",
		},
		{
			name: "absent allow list no mode",
			yaml: `
agents:
  bare: {}
`,
			agent:  "bare",
			reason: "default-deny",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writePolicy(t, tt.yaml)
			eng, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			dec := eng.Evaluate(tt.agent, "any_tool")
			if dec.Allowed() {
				t.Errorf("named agent with no allow list must be DENIED, got %+v", dec)
			}
			if !strings.Contains(dec.Reason, tt.reason) {
				t.Errorf("reason = %q, want to contain %q", dec.Reason, tt.reason)
			}
			if eng.Check(tt.agent, "any_tool") {
				t.Error("Check must also deny (consistent with Evaluate)")
			}
		})
	}
}

func TestFailMode(t *testing.T) {
	path := writePolicy(t, `
agents:
  kit:
    allow: ["*"]
  review:
    allow: ["*"]
    fail_mode: ask
  explicit:
    allow: ["*"]
    fail_mode: deny
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		agent string
		want  Verdict
	}{
		{"kit", Deny},
		{"review", Ask},
		{"explicit", Deny},
		{"unknown", Deny},
	}
	for _, tt := range tests {
		if got := eng.FailModeVerdict(tt.agent, "unextractable-name").Verdict; got != tt.want {
			t.Errorf("FailModeVerdict(%q).Verdict = %v, want %v", tt.agent, got, tt.want)
		}
	}
}

// TestEmptyPolicyFile verifies that an empty policy file loads without error as
// the zero/empty config. This is a regression test for N8306: PR #38 switched
// Load() to yaml.NewDecoder.Decode() which returns io.EOF on empty input (unlike
// yaml.Unmarshal which returned nil), causing empty files to fail instead of
// loading as a no-op policy.
func TestEmptyPolicyFile(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"empty file", ""},
		{"newline only", "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writePolicy(t, tc.content)
			eng, err := Load(path)
			if err != nil {
				t.Fatalf("Load() on %s returned error: %v", tc.name, err)
			}
			// Zero config: no agents configured, every check fail-closed.
			if eng.HasPolicyFor("any_agent") {
				t.Error("empty policy should have no agents configured")
			}
			if eng.Check("any_agent", "any_tool") {
				t.Error("empty policy should deny all tools (fail-closed)")
			}
		})
	}
}

// TestUnknownFieldsRejected verifies that a misspelled control key under an
// agent — e.g. "denny" instead of "deny" — causes Load() to return an error
// instead of silently accepting the typo as a no-op. Without strict decoding a
// misspelled deny/ask/require_approval can void a guardrail with no warning
// (N8300).
func TestUnknownFieldsRejected(t *testing.T) {
	cases := []struct {
		name   string
		yaml   string
		badKey string
	}{
		{
			name:   "misspelled deny as denny",
			badKey: "denny",
			yaml: `
agents:
  kit:
    allow:
      - "nockcc_*"
    denny:
      - "nockcc_kill_switch_set"
`,
		},
		{
			name:   "misspelled require_approvals",
			badKey: "require_approvals",
			yaml: `
agents:
  kit:
    allow:
      - "nockcc_*"
    require_approvals:
      - "nockcc_spend_*"
`,
		},
		{
			name:   "misspelled validate_inputs",
			badKey: "validate_inputs",
			yaml: `
agents:
  kit:
    mode: allow
    validate_inputs:
      - "sqli"
`,
		},
		{
			name:   "unknown top-level key",
			badKey: "agentss",
			yaml: `
agentss:
  kit:
    allow:
      - "nockcc_*"
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writePolicy(t, tc.yaml)
			_, err := Load(path)
			if err == nil {
				t.Fatalf("Load() accepted policy with unknown field %q — must reject it", tc.badKey)
			}
			if !strings.Contains(err.Error(), tc.badKey) {
				t.Errorf("error should name the unknown field %q, got: %v", tc.badKey, err)
			}
		})
	}
}
