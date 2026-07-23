package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunBlockCheck table-drives the core proof-of-block primitive across the
// four outcomes that matter: a real block (PASS), a control that leaks the probe
// (FAIL), and a positive control that never forwards so the block is not real
// (SKIP). This is where the six false-pass lessons are guarded.
func TestRunBlockCheck(t *testing.T) {
	tests := []struct {
		name          string
		controlPolicy string
		enforcePolicy string
		probe         []byte
		denyTool      string
		wantStatus    string
	}{
		{
			name:          "policy deny blocks the probe",
			controlPolicy: permissivePolicyYAML,
			enforcePolicy: denyPolicyYAML,
			probe:         toolCallLine(selftestProbeTool, `{"note":"canary"}`),
			denyTool:      selftestProbeTool,
			wantStatus:    selftestStatusPass,
		},
		{
			name:          "secret argument is flagged",
			controlPolicy: permissivePolicyYAML,
			enforcePolicy: secretsPolicyYAML,
			probe:         toolCallLine(selftestProbeTool, `{"payload":"`+selftestSecret+`"}`),
			wantStatus:    selftestStatusPass,
		},
		{
			// A deliberately-permissive "enforcing" policy must be DETECTED: the
			// probe forwards under it, so the check FAILS rather than lying PASS.
			name:          "permissive enforce policy is caught as a leak",
			controlPolicy: permissivePolicyYAML,
			enforcePolicy: permissivePolicyYAML,
			probe:         toolCallLine(selftestProbeTool, `{"note":"canary"}`),
			wantStatus:    selftestStatusFail,
		},
		{
			// denyTool set but the enforce policy does NOT deny it: the Decision is
			// not Deny, so the check FAILS (policy gap), never a vacuous PASS.
			name:          "deny assertion fails when policy does not deny",
			controlPolicy: permissivePolicyYAML,
			enforcePolicy: permissivePolicyYAML,
			probe:         toolCallLine(selftestProbeTool, `{"note":"canary"}`),
			denyTool:      selftestProbeTool,
			wantStatus:    selftestStatusFail,
		},
		{
			// Positive control that never forwards (the control policy itself denies
			// the probe) must yield SKIP — a block under enforce would be
			// meaningless, so we refuse to call it PASS.
			name:          "positive control failure yields SKIP",
			controlPolicy: denyPolicyYAML,
			enforcePolicy: denyPolicyYAML,
			probe:         toolCallLine(selftestProbeTool, `{"note":"canary"}`),
			denyTool:      selftestProbeTool,
			wantStatus:    selftestStatusSkip,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runBlockCheck(blockCheckSpec{
				name:          "probe",
				controlPolicy: tt.controlPolicy,
				enforcePolicy: tt.enforcePolicy,
				probe:         tt.probe,
				denyTool:      tt.denyTool,
				blockedDetail: "blocked",
				leakedDetail:  "leaked",
			})
			if got.Status != tt.wantStatus {
				t.Fatalf("status = %q, want %q (detail: %s)", got.Status, tt.wantStatus, got.Detail)
			}
		})
	}
}

// TestSelftestCommandProven drives the full `selftest` command against an active
// policy and asserts the end-to-end PROVEN verdict + exit 0, in both human and
// JSON output.
func TestSelftestCommandProven(t *testing.T) {
	policyPath := writePolicyFile(t, "agents:\n  kit:\n    mode: allow\n    deny:\n      - \"*delete*\"\n")

	code, stdout, stderr := runCommandForTest(t, "selftest", "--policy", policyPath)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "VERDICT: PROVEN") || !strings.Contains(stdout, "[PASS]  policy-deny") || !strings.Contains(stdout, "[PASS]  input-validation") {
		t.Fatalf("human output should prove both checks, got:\n%s", stdout)
	}

	code, stdout, stderr = runCommandForTest(t, "selftest", "--policy", policyPath, "--json")
	if code != 0 {
		t.Fatalf("json exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	var report selftestReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("selftest --json emitted invalid JSON: %v\n%s", err, stdout)
	}
	if report.Verdict != "PROVEN" || report.Passed != 2 || report.Failed != 0 {
		t.Fatalf("report = %+v, want PROVEN/2/0", report)
	}
}

// TestSelftestCommandNoActivePolicy asserts the no-vacuous-pass rule: a missing
// or empty active policy exits non-zero and never claims to pass.
func TestSelftestCommandNoActivePolicy(t *testing.T) {
	t.Run("missing policy file", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "nope.yaml")
		code, stdout, stderr := runCommandForTest(t, "selftest", "--policy", missing)
		if code != 1 {
			t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
		if !strings.Contains(stderr, "did not load") {
			t.Fatalf("stderr should report the load failure, got:\n%s", stderr)
		}
	})

	t.Run("no agents governed", func(t *testing.T) {
		policyPath := writePolicyFile(t, "agents: {}\n")
		code, stdout, stderr := runCommandForTest(t, "selftest", "--policy", policyPath)
		if code != 1 {
			t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
		if !strings.Contains(stderr, "governs no agents") {
			t.Fatalf("stderr should report no agents, got:\n%s", stderr)
		}
	})
}

func writePolicyFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
