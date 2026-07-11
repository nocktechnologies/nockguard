package policy

import (
	"strings"
	"testing"
)

// N8695 regression — an unknown validate_input category silently disabled input
// validation.
//
// validate.New appended builtin[c] without checking that c existed, and Load()
// never validated the category set, so a policy typo such as
// validate_input: ["secret"] (for "secrets") or ["sql"] (for "sqli") loaded
// cleanly and produced a validator with ZERO built-in rules. The operator
// believed Phase 2 secret/SQLi/path-traversal filtering was active while
// malicious tool-call arguments were forwarded unchecked — fail-open in a
// security control.
//
// Fix: reject any validate_input value not in the supported set
// (sqli, path_traversal, secrets) at Load() (fail loud) AND in validate.New
// (defense in depth for any direct caller).

// TestUnknownValidateInputCategoryRejectedAtLoad — Load() must error on a
// validate_input typo rather than accept a policy whose validator silently has
// no rules. Before the fix Load() accepted this policy without complaint.
func TestUnknownValidateInputCategoryRejectedAtLoad(t *testing.T) {
	path := writePolicy(t, `
agents:
  kit:
    allow:
      - "nockcc_*"
    validate_input:
      - "secret"
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() must reject a policy with an unknown validate_input category (N8695 regression) — it silently disabled input validation before the fix")
	}
	if !strings.Contains(err.Error(), "secret") {
		t.Errorf("error should name the unknown category, got: %v", err)
	}
	if !strings.Contains(err.Error(), "secrets") {
		t.Errorf("error should list the valid categories to guide the fix, got: %v", err)
	}
}

// A short-form typo of an existing category ("sql" for "sqli") is the same class
// of fail-open bug and must also be rejected at Load().
func TestShortFormValidateInputTypoRejectedAtLoad(t *testing.T) {
	path := writePolicy(t, `
agents:
  kit:
    validate_input:
      - "sql"
`)
	if _, err := Load(path); err == nil {
		t.Error("Load() must reject validate_input: [\"sql\"] (typo for \"sqli\")")
	}
}

// The supported categories must still load and, once loaded, build a validator
// with active rules — the guard must not over-reject a correct config.
func TestKnownValidateInputCategoriesStillLoad(t *testing.T) {
	path := writePolicy(t, `
agents:
  kit:
    validate_input:
      - "sqli"
      - "path_traversal"
      - "secrets"
`)
	eng, err := Load(path)
	if err != nil {
		t.Fatalf("a policy with valid validate_input categories must load: %v", err)
	}
	v, err := eng.ValidatorFor("kit")
	if err != nil {
		t.Fatalf("ValidatorFor must succeed for a valid config: %v", err)
	}
	if v == nil || !v.Enabled() {
		t.Fatal("a validator built from valid categories must be enabled (non-empty rule set)")
	}
}
