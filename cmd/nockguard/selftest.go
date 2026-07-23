package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/nocktechnologies/nockguard/internal/policy"
	"github.com/nocktechnologies/nockguard/internal/proxy"
	"github.com/nocktechnologies/nockguard/internal/validate"
)

// The `selftest` command is a proof-of-BLOCK: it proves NockGuard's live
// enforcement path actually DENIES a policy-denied tool call and FLAGS a
// secret-bearing argument — the trust primitive of an MCP firewall. It is
// deliberately distinct from `audit verify`, which proves the audit TRAIL is
// intact; a firewall can keep a perfect trail while silently forwarding every
// call. selftest closes that gap by driving benign canary probes through the
// SAME proxy gate real agent traffic takes (internal/proxy.Probe), not a mock.
//
// Every check runs a POSITIVE CONTROL first: it proves the probe WOULD be
// forwarded (allowed / arg passes) WITHOUT the deny rule or validation, so a
// block under the enforcing policy is real — not a missing tool, an unwired
// probe, or a setup error. If the positive control fails, the check is SKIP
// (inconclusive), never PASS. A block that coincides with a real policy Decision
// of Deny is distinguished from an inconclusive error path.
//
// Exit codes mirror `verify`: 0 = enforcement PROVEN (>=1 PASS, 0 FAIL), 2 = an
// enforcement GAP (>=1 FAIL — a denied tool was allowed or a secret passed
// through, the dangerous case), 1 = INCONCLUSIVE / usage / no active policy.
// A firewall that proves nothing (all SKIP, or no active policy) is NOT passing.

const (
	selftestAgent      = "nockguard-selftest"
	selftestProbeTool  = "nockguard-selftest-probe"
	selftestStatusPass = "PASS"
	selftestStatusFail = "FAIL"
	selftestStatusSkip = "SKIP"
)

// selftestSecret is a SYNTHETIC secret-shaped canary: it matches the built-in
// "openai-key" detector (sk- followed by 20+ alphanumerics) but is not a real
// credential — no live secret is ever embedded. It only needs to trip the
// secrets category so the input-validation check has something to catch.
const selftestSecret = "sk-NockguardSelftestCanary000000000000"

type selftestCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type selftestReport struct {
	Verdict    string          `json:"verdict"`
	Policy     string          `json:"policy"`
	ProbeAgent string          `json:"probe_agent"`
	Passed     int             `json:"passed"`
	Failed     int             `json:"failed"`
	Skipped    int             `json:"skipped"`
	Checks     []selftestCheck `json:"checks"`
}

func runSelftest(args []string) int {
	var policyPath string
	jsonOutput := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			jsonOutput = true
		case "--policy":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --policy requires a value")
				return 1
			}
			i++
			policyPath = args[i]
		default:
			fmt.Fprintf(os.Stderr, "error: unknown flag %q\n", args[i])
			return 1
		}
	}

	if policyPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot determine home directory: %v\n", err)
			return 1
		}
		policyPath = home + "/.nockguard/policy.yaml"
	}

	// Step 1: load the ACTIVE policy the firewall uses. A firewall whose own
	// config will not load (or governs no agents) is not "passing" — fail with a
	// setup error before proving anything, honoring the no-vacuous-pass rule.
	active, err := policy.Load(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: active policy %s did not load: %v\n", policyPath, err)
		fmt.Fprintln(os.Stderr, "VERDICT: INCONCLUSIVE (the firewall's own policy is unusable)")
		return 1
	}
	if active.AgentCount() == 0 {
		fmt.Fprintf(os.Stderr, "error: active policy %s governs no agents — nothing is enforced\n", policyPath)
		fmt.Fprintln(os.Stderr, "VERDICT: INCONCLUSIVE (no policy rules to enforce)")
		return 1
	}

	checks := []selftestCheck{
		checkPolicyDeny(),
		checkInputValidation(),
	}

	report := selftestReport{Policy: policyPath, ProbeAgent: selftestAgent}
	for _, c := range checks {
		switch c.Status {
		case selftestStatusPass:
			report.Passed++
		case selftestStatusFail:
			report.Failed++
		default:
			report.Skipped++
		}
	}
	report.Checks = checks

	// Exit 0 only when at least one check PASSED and none FAILED — a firewall
	// that proved nothing (all SKIP) does not pass.
	var code int
	switch {
	case report.Failed > 0:
		report.Verdict = "GAP"
		code = 2
	case report.Passed > 0:
		report.Verdict = "PROVEN"
		code = 0
	default:
		report.Verdict = "INCONCLUSIVE"
		code = 1
	}

	if jsonOutput {
		writeJSON(report)
		return code
	}

	fmt.Println("nockguard selftest — proof of BLOCK")
	fmt.Printf("active policy loaded: %s (governs %d agent(s))\n", policyPath, active.AgentCount())
	fmt.Println("the checks below prove the enforcement engine BLOCKS, using benign canary probe policies:")
	fmt.Println()
	for _, c := range checks {
		fmt.Printf("  [%s]  %-18s %s\n", c.Status, c.Name, c.Detail)
	}
	fmt.Printf("\n%d passed, %d failed, %d skipped\n", report.Passed, report.Failed, report.Skipped)
	fmt.Printf("VERDICT: %s\n", report.Verdict)
	return code
}

// blockCheckSpec parameterizes one proof-of-block check: drive probe through a
// permissive control policy (must forward) then through an enforcing policy
// (must be blocked). denyTool, when non-empty, additionally asserts the enforce
// engine returns a real Deny Decision for that tool — the difference between a
// policy deny and an inconclusive error path. Empty denyTool is used when the
// block is expected at a LATER gate (e.g. input validation) where the policy
// verdict is Allow but the argument is rejected. controlPolicy is always the
// permissive policy in production; it is a field so a test can inject a control
// that does NOT forward and exercise the positive-control-fails → SKIP path.
type blockCheckSpec struct {
	name          string
	controlPolicy string
	enforcePolicy string
	probe         []byte
	denyTool      string
	// blockedDetail / leakedDetail phrase the PASS / FAIL outcomes for this check.
	blockedDetail string
	leakedDetail  string
}

func checkPolicyDeny() selftestCheck {
	return runBlockCheck(blockCheckSpec{
		name:          "policy-deny",
		controlPolicy: permissivePolicyYAML,
		enforcePolicy: denyPolicyYAML,
		probe:         toolCallLine(selftestProbeTool, `{"note":"canary"}`),
		denyTool:      selftestProbeTool,
		blockedDetail: fmt.Sprintf("denied tool %q blocked at the gate; positive control allowed it without the deny rule", selftestProbeTool),
		leakedDetail:  fmt.Sprintf("DENIED tool %q was FORWARDED — the block leaked through the gate", selftestProbeTool),
	})
}

func checkInputValidation() selftestCheck {
	return runBlockCheck(blockCheckSpec{
		name:          "input-validation",
		controlPolicy: permissivePolicyYAML,
		enforcePolicy: secretsPolicyYAML,
		probe:         toolCallLine(selftestProbeTool, fmt.Sprintf(`{"payload":%q}`, selftestSecret)),
		blockedDetail: "synthetic secret argument flagged and blocked at the gate; positive control passed it without validation",
		leakedDetail:  "secret-bearing argument was FORWARDED — input validation did not flag it",
	})
}

// runBlockCheck executes one proof-of-block check. It FIRST runs the positive
// control (probe must forward under the permissive policy) so a block under the
// enforcing policy is real — not a missing tool, an unwired probe, or a setup
// error. A positive-control miss returns SKIP, never PASS. It then confirms the
// enforcing policy blocks the probe at the gate (and, when denyTool is set, that
// the engine's Decision is genuinely Deny rather than an error). PASS iff blocked;
// FAIL iff forwarded (the control leaked).
func runBlockCheck(spec blockCheckSpec) selftestCheck {
	c := selftestCheck{Name: spec.name}

	// Positive control: the probe MUST forward without the control under test.
	controlProxy, err := selftestProxy(spec.controlPolicy)
	if err != nil {
		return skip(c, "positive control could not build permissive policy: "+err.Error())
	}
	forwarded, _, err := controlProxy.Probe(spec.probe)
	if err != nil {
		return skip(c, "positive control errored driving the probe: "+err.Error())
	}
	if !forwarded {
		return skip(c, "positive control did not forward the probe — the canary is not wired; a block would be meaningless")
	}

	// Enforce: build the engine once so we can both inspect the Decision and run
	// the gate over it.
	enforceEngine, err := policy.LoadBytes([]byte(spec.enforcePolicy))
	if err != nil {
		return skip(c, "could not build enforcing policy: "+err.Error())
	}
	// Distinguish a real policy Deny from an error path (tool-not-found, etc.).
	if spec.denyTool != "" {
		dec := enforceEngine.Evaluate(selftestAgent, spec.denyTool)
		if dec.Verdict != policy.Deny {
			c.Status = selftestStatusFail
			c.Detail = fmt.Sprintf("policy did NOT deny %q — verdict was %q (%s)", spec.denyTool, dec.Verdict, dec.Reason)
			return c
		}
	}
	validator, err := enforceEngine.ValidatorFor(selftestAgent)
	if err != nil {
		return skip(c, "could not build input validator: "+err.Error())
	}
	enforceProxy := proxyForEngine(enforceEngine, validator)
	forwarded, _, err = enforceProxy.Probe(spec.probe)
	if err != nil {
		return skip(c, "enforce path errored driving the probe: "+err.Error())
	}
	if forwarded {
		c.Status = selftestStatusFail
		c.Detail = spec.leakedDetail
		return c
	}
	c.Status = selftestStatusPass
	c.Detail = spec.blockedDetail
	return c
}

// skip stamps a check as SKIP (inconclusive) with a reason.
func skip(c selftestCheck, detail string) selftestCheck {
	c.Status = selftestStatusSkip
	c.Detail = detail
	return c
}

// Canary policies. Every one governs only the selftest probe agent and is loaded
// through the real policy loader (policy.LoadBytes), so a self-test PASS reflects
// the same parse + validation the firewall runs. mode: allow makes the positive
// control forward everything; the deny rule / validate_input isolate exactly one
// control under test.
const permissivePolicyYAML = `agents:
  nockguard-selftest:
    mode: allow
`

const denyPolicyYAML = `agents:
  nockguard-selftest:
    mode: allow
    deny:
      - nockguard-selftest-probe
`

const secretsPolicyYAML = `agents:
  nockguard-selftest:
    mode: allow
    validate_input:
      - secrets
`

// selftestProxy builds a proxy wired to a canary policy parsed from YAML,
// including the policy's input validator, so Probe exercises both the policy gate
// and Phase 2 validation exactly as production does.
func selftestProxy(policyYAML string) (*proxy.StdioProxy, error) {
	engine, err := policy.LoadBytes([]byte(policyYAML))
	if err != nil {
		return nil, err
	}
	validator, err := engine.ValidatorFor(selftestAgent)
	if err != nil {
		return nil, err
	}
	return proxyForEngine(engine, validator), nil
}

// proxyForEngine constructs a minimal proxy for the probe agent. limiter, audit,
// forwarder, and trust are left nil — every one is nil-safe (guarded by Enabled)
// — so Probe runs the policy + validation gates with no side effects.
func proxyForEngine(engine *policy.Engine, validator *validate.Validator) *proxy.StdioProxy {
	// Discard the proxy's per-call ALLOW/DENY/BLOCK log: the selftest narrates
	// each outcome itself, so the internal gate chatter would only be noise.
	logger := log.New(io.Discard, "", 0)
	return proxy.NewStdioProxy(nil, selftestAgent, engine, validator, nil, nil, nil, logger)
}

// toolCallLine renders a single JSON-RPC tools/call line for the probe tool with
// the given raw-JSON arguments object.
func toolCallLine(tool, argumentsJSON string) []byte {
	return []byte(fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":%s}}`,
		tool, argumentsJSON,
	))
}
