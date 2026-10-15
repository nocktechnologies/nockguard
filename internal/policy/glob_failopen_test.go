package policy

import (
	"fmt"
	"strings"
	"testing"
)

// N8180 regression — a malformed glob in a deny rule silently failed OPEN.
//
// matchPattern did `matched, _ := filepath.Match(pattern, tool)`, discarding the
// error. A malformed wildcard deny (e.g. "nockcc_[spend*", an unclosed character
// class followed by a wildcard) returned ErrBadPattern, was swallowed to
// matched=false, so the deny silently voided and a broad allow let the call
// through — fail-open in the policy engine's strongest control, while LimiterFor
// and validate.New both fail LOUD on misconfiguration.
//
// Fix: validate every glob at Load() (fail loud) AND treat a filepath.Match
// error at evaluate-time as fail-CLOSED for deny.

// TestMalformedGlobRejectedAtLoad — Load() must error on a malformed glob rather
// than accept a policy whose deny silently no-matches. Before the fix Load()
// accepted this policy without complaint.
func TestMalformedGlobRejectedAtLoad(t *testing.T) {
	path := writePolicy(t, `
agents:
  kit:
    allow:
      - "nockcc_*"
    deny:
      - "nockcc_[spend*"
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() must reject a policy with a malformed deny glob (N8180 regression) — it silently failed open before the fix")
	}
	if !strings.Contains(err.Error(), "malformed glob") {
		t.Errorf("error should name the malformed glob, got: %v", err)
	}
}

// A malformed glob in any rule list (not just deny) is a misconfiguration and
// must fail loud at Load().
func TestMalformedGlobInAllowRejectedAtLoad(t *testing.T) {
	path := writePolicy(t, `
agents:
  kit:
    allow:
      - "nockcc_[bad*"
`)
	if _, err := Load(path); err == nil {
		t.Error("Load() must reject a malformed allow glob too")
	}
}

// Well-formed globs (including a valid character class) must still load.
func TestWellFormedGlobsStillLoad(t *testing.T) {
	path := writePolicy(t, `
agents:
  kit:
    allow:
      - "nockcc_*"
      - "nockcc_[a-z]*"
    deny:
      - "*_delete"
      - "nockcc_kill_switch_set"
`)
	if _, err := Load(path); err != nil {
		t.Errorf("a policy with well-formed globs must load: %v", err)
	}
}

// TestMalformedDenyGlobFailsClosedAtEvaluate — the evaluate-time backstop. Even
// if a malformed deny glob ever reaches the engine (bypassing Load's validation),
// Evaluate must FAIL CLOSED (deny), never silently allow the call through a broad
// allow rule. Built directly from a Config so the Load() validation does not
// intercept it, isolating the evaluate-time behavior.
//
// Before the fix: allow ["nockcc_*"], deny ["nockcc_[spend*"] =>
// Evaluate("kit","nockcc_spend_add") = ALLOW (deny silently void). After: DENY.
func TestMalformedDenyGlobFailsClosedAtEvaluate(t *testing.T) {
	eng := &Engine{config: Config{
		Agents: map[string]AgentPolicy{
			"kit": {
				Allow: []string{"nockcc_*"},
				Deny:  []string{"nockcc_[spend*"}, // malformed: unclosed character class
			},
		},
	}}

	dec := eng.Evaluate("kit", "nockcc_spend_add")
	if dec.Allowed() {
		t.Fatalf("a malformed deny glob must NOT fail open — Evaluate allowed the call (N8180 regression); reason: %q", dec.Reason)
	}
	if dec.Verdict != Deny {
		t.Errorf("expected fail-closed Deny on a malformed deny glob, got %v (reason: %q)", dec.Verdict, dec.Reason)
	}

	// The boolean Check view must agree (it is the boolean projection of Evaluate).
	if eng.Check("kit", "nockcc_spend_add") {
		t.Error("Check must also fail closed on a malformed deny glob")
	}
}

// Guardrail: a well-formed deny still denies, and a non-matching deny still lets
// an allowed tool through — the fix does not over-deny legitimate calls.
func TestWellFormedDenyStillBehaves(t *testing.T) {
	eng := &Engine{config: Config{
		Agents: map[string]AgentPolicy{
			"kit": {
				Allow: []string{"nockcc_*"},
				Deny:  []string{"nockcc_kill_*"},
			},
		},
	}}
	if eng.Check("kit", "nockcc_kill_switch_set") {
		t.Error("a well-formed deny must still deny its match")
	}
	if !eng.Check("kit", "nockcc_spend_add") {
		t.Error("a tool not matched by the deny but matched by allow must still be allowed")
	}
}

func TestPolicyGlobSyntaxAcrossRuleFields(t *testing.T) {
	fields := []struct {
		name string
	}{
		{name: "deny"},
		{name: "ask"},
		{name: "require_approval"},
		{name: "allow"},
		{name: "shadow"},
	}
	patterns := []struct {
		name      string
		pattern   string
		matching  string
		nonmatch  string
		malformed bool
	}{
		{name: "question", pattern: "exec?", matching: "exec1", nonmatch: "exec12"},
		{name: "class", pattern: "deploy_[ab]", matching: "deploy_a", nonmatch: "deploy_c"},
		{name: "star", pattern: "deploy_*", matching: "deploy_prod", nonmatch: "read_file"},
		{name: "literal", pattern: "deploy_prod", matching: "deploy_prod", nonmatch: "deploy_dev"},
		{name: "malformed_class", pattern: "deploy_[ab", malformed: true},
	}

	for _, field := range fields {
		for _, pattern := range patterns {
			t.Run(field.name+"/"+pattern.name, func(t *testing.T) {
				policyText := fmt.Sprintf("agents:\n  kit:\n    mode: allow\n    %s:\n      - %q\n", field.name, pattern.pattern)
				eng, err := LoadBytes([]byte(policyText))
				if pattern.malformed {
					if err == nil || !strings.Contains(err.Error(), "malformed glob") {
						t.Fatalf("LoadBytes() error = %v, want malformed glob error", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("LoadBytes(): %v", err)
				}

				for _, sample := range []struct {
					tool    string
					matches bool
				}{{pattern.matching, true}, {pattern.nonmatch, false}} {
					if field.name == "require_approval" {
						if got := eng.RequiresApproval("kit", sample.tool); got != sample.matches {
							t.Errorf("RequiresApproval(%q) = %v, want %v", sample.tool, got, sample.matches)
						}
						continue
					}

					decision := eng.Evaluate("kit", sample.tool)
					switch field.name {
					case "deny":
						want := Allow
						if sample.matches {
							want = Deny
						}
						if decision.Verdict != want {
							t.Errorf("Evaluate(%q).Verdict = %v, want %v", sample.tool, decision.Verdict, want)
						}
					case "ask":
						want := Allow
						if sample.matches {
							want = Ask
						}
						if decision.Verdict != want {
							t.Errorf("Evaluate(%q).Verdict = %v, want %v", sample.tool, decision.Verdict, want)
						}
					case "allow":
						want := Deny
						if sample.matches {
							want = Allow
						}
						if decision.Verdict != want {
							t.Errorf("Evaluate(%q).Verdict = %v, want %v", sample.tool, decision.Verdict, want)
						}
					case "shadow":
						if decision.Verdict != Allow {
							t.Errorf("Evaluate(%q).Verdict = %v, want Allow", sample.tool, decision.Verdict)
						}
						want := !sample.matches
						if decision.ShadowWouldDeny != want {
							t.Errorf("Evaluate(%q).ShadowWouldDeny = %v, want %v", sample.tool, decision.ShadowWouldDeny, want)
						}
					}
				}
			})
		}
	}
}

func TestGlobPatternOverlapUsesPolicyGlobSyntax(t *testing.T) {
	tests := []struct {
		name         string
		pattern      string
		literal      string
		wantDisjoint bool
	}{
		{name: "question overlaps literal", pattern: "exec?", literal: "exec1", wantDisjoint: false},
		{name: "question misses literal", pattern: "exec?", literal: "exec12", wantDisjoint: true},
		{name: "class overlaps literal", pattern: "deploy_[ab]", literal: "deploy_a", wantDisjoint: false},
		{name: "class misses literal", pattern: "deploy_[ab]", literal: "deploy_c", wantDisjoint: true},
		{name: "star overlaps literal", pattern: "deploy_*", literal: "deploy_prod", wantDisjoint: false},
		{name: "star misses literal", pattern: "deploy_*", literal: "read_file", wantDisjoint: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isGlobPatternDisjoint(tt.pattern, tt.literal); got != tt.wantDisjoint {
				t.Errorf("isGlobPatternDisjoint(%q, %q) = %v, want %v", tt.pattern, tt.literal, got, tt.wantDisjoint)
			}
		})
	}
}
