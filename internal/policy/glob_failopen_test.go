package policy

import (
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
