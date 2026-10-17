package policy

import (
	"fmt"
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

func policyWithPatternRule(field, pattern string) []byte {
	if field == "allow" {
		return []byte(fmt.Sprintf("agents:\n  kit:\n    mode: allow\n    allow: [%q]\n", pattern))
	}
	return []byte(fmt.Sprintf("agents:\n  kit:\n    mode: allow\n    allow: [\"*\"]\n    %s: [%q]\n", field, pattern))
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

func TestAgentPolicyFallbackPreservesNamedEmptyPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, policy string
		found        bool
		verdict      Verdict
	}{
		{"named empty overrides default", "agents:\n  kit: {}\n  default:\n    mode: allow\n", true, Deny},
		{"named allow overrides default", "agents:\n  kit:\n    mode: allow\n  default:\n    mode: deny\n", true, Allow},
		{"unknown uses default", "agents:\n  default:\n    mode: allow\n", true, Allow},
		{"unknown without default fails closed", "agents: {}\n", false, Deny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng, err := LoadBytes([]byte(tc.policy))
			if err != nil {
				t.Fatal(err)
			}
			if got := eng.HasPolicyFor("kit"); got != tc.found {
				t.Errorf("HasPolicyFor = %v, want %v", got, tc.found)
			}
			if got := eng.Evaluate("kit", "read").Verdict; got != tc.verdict {
				t.Errorf("Evaluate verdict = %v, want %v", got, tc.verdict)
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

// TestInjectRulesValidation tests load-time validation of inject rules.
func TestInjectRulesValidation(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{
			name: "valid inject rule",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["test_tool"]
        ref: "env:SECRET"
        arg: "headers.auth"
`,
			wantErr: false,
		},
		{
			name: "inject with template",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["test_tool"]
        ref: "env:SECRET"
        arg: "headers.auth"
        template: "Bearer {secret}"
`,
			wantErr: false,
		},
		{
			name: "empty tools",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: []
        ref: "env:SECRET"
        arg: "headers.auth"
`,
			wantErr: true,
		},
		{
			name: "empty ref",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["test_tool"]
        ref: ""
        arg: "headers.auth"
`,
			wantErr: true,
		},
		{
			name: "empty arg",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["test_tool"]
        ref: "env:SECRET"
        arg: ""
`,
			wantErr: true,
		},
		{
			name: "bare * glob",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["*"]
        ref: "env:SECRET"
        arg: "headers.auth"
`,
			wantErr: true,
		},
		{
			name: "bare ** glob",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["**"]
        ref: "env:SECRET"
        arg: "headers.auth"
`,
			wantErr: true,
		},
		{
			name: "arg starts with dot",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["test_tool"]
        ref: "env:SECRET"
        arg: ".headers.auth"
`,
			wantErr: true,
		},
		{
			name: "arg ends with dot",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["test_tool"]
        ref: "env:SECRET"
        arg: "headers.auth."
`,
			wantErr: true,
		},
		{
			name: "arg is dot",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["test_tool"]
        ref: "env:SECRET"
        arg: "."
`,
			wantErr: true,
		},
		{
			name: "bad template no placeholder",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["test_tool"]
        ref: "env:SECRET"
        arg: "headers.auth"
        template: "Bearer no_placeholder"
`,
			wantErr: true,
		},
		{
			name: "bad template multiple placeholders",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["test_tool"]
        ref: "env:SECRET"
        arg: "headers.auth"
        template: "Bearer {secret} {secret}"
`,
			wantErr: true,
		},
		{
			name: "unknown scheme",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["test_tool"]
        ref: "vault:mysecret"
        arg: "headers.auth"
`,
			wantErr: true,
		},
		{
			name: "conflicting rules same tool and arg",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["test_tool"]
        ref: "env:SECRET1"
        arg: "headers.auth"
      - tools: ["test_tool"]
        ref: "env:SECRET2"
        arg: "headers.auth"
`,
			wantErr: true,
		},
		{
			name: "file scheme with absolute path",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["test_tool"]
        ref: "file:/etc/secret"
        arg: "headers.auth"
`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writePolicy(t, tt.yaml)
			_, err := Load(path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Load() wantErr=%v, got err=%v", tt.wantErr, err)
			}
		})
	}
}

// TestInjectRulesFor tests the InjectRulesFor engine method.
func TestInjectRulesFor(t *testing.T) {
	yaml := `
agents:
  test:
    mode: allow
    inject:
      - tools: ["github_*"]
        ref: "env:GITHUB_TOKEN"
        arg: "headers.auth"
      - tools: ["slack_post_*"]
        ref: "env:SLACK_TOKEN"
        arg: "token"
  default:
    mode: allow
    inject:
      - tools: ["openai_*"]
        ref: "env:OPENAI_KEY"
        arg: "api_key"
`
	path := writePolicy(t, yaml)
	eng, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	tests := []struct {
		agent    string
		tool     string
		wantRefs []string // Expected refs from matching rules
	}{
		{"test", "github_create_repo", []string{"env:GITHUB_TOKEN"}},
		{"test", "slack_post_message", []string{"env:SLACK_TOKEN"}},
		{"test", "github_list_issues", []string{"env:GITHUB_TOKEN"}},
		{"test", "unknown_tool", nil},
		{"other", "openai_create_completion", []string{"env:OPENAI_KEY"}},
		{"other", "unknown", nil},
	}

	for _, tt := range tests {
		rules := eng.InjectRulesFor(tt.agent, tt.tool)
		var gotRefs []string
		for _, rule := range rules {
			gotRefs = append(gotRefs, rule.Ref)
		}
		if len(gotRefs) != len(tt.wantRefs) {
			t.Errorf("InjectRulesFor(%s, %s): got %v, want %v", tt.agent, tt.tool, gotRefs, tt.wantRefs)
		} else {
			for i, ref := range gotRefs {
				if ref != tt.wantRefs[i] {
					t.Errorf("InjectRulesFor(%s, %s): got ref %s, want %s", tt.agent, tt.tool, ref, tt.wantRefs[i])
				}
			}
		}
	}
}

// TestInjectWarnings verifies that tools appearing in multiple inject rules
// (with different arg paths) produce a warning.
func TestInjectWarnings(t *testing.T) {
	yaml := `
agents:
  test:
    mode: allow
    inject:
      - tools: ["github_create_issue", "github_list_issues"]
        ref: "env:GITHUB_TOKEN_1"
        arg: "headers.auth1"
      - tools: ["github_create_issue"]  # same tool as above rule
        ref: "env:GITHUB_TOKEN_2"
        arg: "headers.auth2"
`
	path := writePolicy(t, yaml)
	eng, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	warnings := eng.Warnings()
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}

	warning := warnings[0]
	if !strings.Contains(warning, "github_create_issue") {
		t.Errorf("warning should name the tool glob: %s", warning)
	}
	if !strings.Contains(warning, "test") {
		t.Errorf("warning should name the agent: %s", warning)
	}
}

// TestInjectGlobOverlap verifies that glob patterns matching each other are rejected.
func TestInjectGlobOverlap(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{
			name: "identical globs OK if different arg",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["github_*"]
        ref: "env:SECRET1"
        arg: "auth1"
      - tools: ["github_*"]
        ref: "env:SECRET2"
        arg: "auth2"
`,
			wantErr: false,
		},
		{
			name: "overlapping glob patterns rejected",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["github_*"]
        ref: "env:SECRET1"
        arg: "auth"
      - tools: ["github_create_*"]
        ref: "env:SECRET2"
        arg: "auth"
`,
			wantErr: true,
		},
		{
			name: "glob matching literal rejected",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["github_*"]
        ref: "env:SECRET1"
        arg: "auth"
      - tools: ["github_create_issue"]
        ref: "env:SECRET2"
        arg: "auth"
`,
			wantErr: true,
		},
		{
			name: "question mark glob matching literal rejected",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["exec?"]
        ref: "env:SECRET1"
        arg: "auth"
      - tools: ["exec1"]
        ref: "env:SECRET2"
        arg: "auth"
`,
			wantErr: true,
		},
		{
			name: "character class glob matching literal rejected",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["deploy_[ab]"]
        ref: "env:SECRET1"
        arg: "auth"
      - tools: ["deploy_b"]
        ref: "env:SECRET2"
        arg: "auth"
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writePolicy(t, tt.yaml)
			_, err := Load(path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Load() wantErr=%v, got err=%v", tt.wantErr, err)
			}
		})
	}
}

func TestPolicyPatternMatchingAcrossRuleFields(t *testing.T) {
	rules := []string{"deny", "ask", "require_approval", "allow", "shadow"}
	patterns := []struct {
		name        string
		pattern     string
		match       string
		nonMatching string
	}{
		{name: "question mark", pattern: "exec?", match: "exec1", nonMatching: "exec12"},
		{name: "character class", pattern: "deploy_[ab]", match: "deploy_a", nonMatching: "deploy_c"},
		{name: "asterisk", pattern: "read_*", match: "read_file", nonMatching: "write_file"},
		{name: "literal", pattern: "nockcc_nock_claim", match: "nockcc_nock_claim", nonMatching: "nockcc_nock_claims"},
	}

	for _, rule := range rules {
		t.Run(rule, func(t *testing.T) {
			for _, pattern := range patterns {
				t.Run(pattern.name, func(t *testing.T) {
					engine, err := LoadBytes(policyWithPatternRule(rule, pattern.pattern))
					if err != nil {
						t.Fatalf("LoadBytes: %v", err)
					}

					for _, candidate := range []struct {
						tool string
						want bool
					}{{pattern.match, true}, {pattern.nonMatching, false}} {
						var got bool
						switch rule {
						case "deny":
							got = engine.Evaluate("kit", candidate.tool).Verdict == Deny
						case "ask":
							got = engine.Evaluate("kit", candidate.tool).Verdict == Ask
						case "require_approval":
							got = engine.RequiresApproval("kit", candidate.tool)
						case "allow":
							got = engine.Evaluate("kit", candidate.tool).Verdict == Allow
						case "shadow":
							got = !engine.Evaluate("kit", candidate.tool).ShadowWouldDeny
						}
						if got != candidate.want {
							t.Errorf("rule %q with pattern %q on %q matched = %v, want %v", rule, pattern.pattern, candidate.tool, got, candidate.want)
						}
					}
				})
			}
		})
	}
}

func TestPolicyPatternMalformedClassRejectedForEveryRuleField(t *testing.T) {
	for _, field := range []string{"deny", "ask", "require_approval", "allow", "shadow"} {
		t.Run(field, func(t *testing.T) {
			if _, err := LoadBytes(policyWithPatternRule(field, "deploy_[ab")); err == nil {
				t.Fatalf("LoadBytes accepted malformed class in %s rules", field)
			}
		})
	}
}

// This negative control failed before Nock #11811: `?` was validated as glob
// syntax at load time but evaluated as literal text, letting exec1 through.
func TestDenyQuestionMarkGlobMatchesExecNumber(t *testing.T) {
	engine, err := LoadBytes([]byte(`
agents:
  kit:
    mode: allow
    allow: ["*"]
    deny: ["exec?"]
`))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if decision := engine.Evaluate("kit", "exec1"); decision.Verdict != Deny {
		t.Fatalf("deny [\"exec?\"] let exec1 through: %+v", decision)
	}
}

func TestPolicyGlobSlashBoundary(t *testing.T) {
	if matchPattern("*", "read/subtool") {
		t.Fatal("path.Match star should not cross a slash in a tool name")
	}
	if !matchPattern("read/*", "read/subtool") {
		t.Fatal("path.Match pattern with an explicit slash should match the tool name")
	}
}

// TestInjectSameArgConflictDetection tests load-time detection of conflicting rules.
func TestInjectSameArgConflictDetection(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{
			name: "same-arg literal vs literal different OK",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["github_create_issue"]
        ref: "env:SECRET1"
        arg: "auth"
      - tools: ["github_list_issues"]
        ref: "env:SECRET2"
        arg: "auth"
`,
			wantErr: false,
		},
		{
			name: "same-arg literal vs matching glob reject",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["github_create_issue"]
        ref: "env:SECRET1"
        arg: "auth"
      - tools: ["github_*"]
        ref: "env:SECRET2"
        arg: "auth"
`,
			wantErr: true,
		},
		{
			name: "same-arg glob with nested prefixes reject",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["github_*"]
        ref: "env:SECRET1"
        arg: "auth"
      - tools: ["github_create_*"]
        ref: "env:SECRET2"
        arg: "auth"
`,
			wantErr: true,
		},
		{
			name: "literal vs non-matching glob OK",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["slack_create_issue"]
        ref: "env:SECRET1"
        arg: "auth"
      - tools: ["github_*"]
        ref: "env:SECRET2"
        arg: "auth"
`,
			wantErr: false,
		},
		{
			name: "overlapping globs different args OK",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["github_*"]
        ref: "env:SECRET1"
        arg: "headers.Authorization"
      - tools: ["github_create_*"]
        ref: "env:SECRET2"
        arg: "headers.SecondaryToken"
`,
			wantErr: false,
		},
		{
			name: "glob vs glob same arg reject",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["github_*_issue"]
        ref: "env:SECRET1"
        arg: "auth"
      - tools: ["github_*_repo"]
        ref: "env:SECRET2"
        arg: "auth"
`,
			wantErr: true,
		},
		{
			name: "character class globs same arg reject",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["github_*[0-9]"]
        ref: "env:SECRET1"
        arg: "auth"
      - tools: ["github_*5"]
        ref: "env:SECRET2"
        arg: "auth"
`,
			wantErr: true,
		},
		{
			name: "glob vs glob with empty suffix same arg reject",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["github_*_issue"]
        ref: "env:SECRET1"
        arg: "auth"
      - tools: ["github_*"]
        ref: "env:SECRET2"
        arg: "auth"
`,
			wantErr: true,
		},
		{
			name: "same-arg overlapping-prefix globs reject",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["github_*"]
        ref: "env:SECRET1"
        arg: "auth"
      - tools: ["github_create_*"]
        ref: "env:SECRET2"
        arg: "auth"
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writePolicy(t, tt.yaml)
			_, err := Load(path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Load() wantErr=%v, got err=%v", tt.wantErr, err)
			}
		})
	}
}

// TestInjectValidateGlobSyntax tests that validateGlob rejects malformed patterns.
func TestInjectValidateGlobSyntax(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{
			name: "malformed bracket glob rejects",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["github_["]
        ref: "env:SECRET1"
        arg: "auth"
`,
			wantErr: true,
		},
		{
			name: "valid question mark glob loads",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["github_?"]
        ref: "env:SECRET1"
        arg: "auth"
`,
			wantErr: false,
		},
		{
			name: "valid mixed globs load",
			yaml: `
agents:
  test:
    mode: allow
    inject:
      - tools: ["github_[a-z]*_issue"]
        ref: "env:SECRET1"
        arg: "auth"
`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writePolicy(t, tt.yaml)
			_, err := Load(path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Load() wantErr=%v, got err=%v", tt.wantErr, err)
			}
		})
	}
}
