package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/nocktechnologies/nockguard/internal/approval"
	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/evidence"
	"github.com/nocktechnologies/nockguard/internal/policy"
	"github.com/nocktechnologies/nockguard/internal/proxy"
	"github.com/nocktechnologies/nockguard/internal/proxy/forwardhttp"
	"github.com/nocktechnologies/nockguard/internal/trust"
	"gopkg.in/yaml.v3"
)

// buildApprover wires the Phase 5 approval gate. For now: a deterministic test
// seam (NOCKGUARD_APPROVAL_TEST=approve|deny) used by e2e tests, otherwise no
// approver (nil). With nil, BOTH native `ask` rules and legacy
// `require_approval` rules fail CLOSED — a covered call is denied, never
// forwarded (N8328: require_approval used to fail open here).
func buildApprover(logger *log.Logger) approval.Approver {
	switch os.Getenv("NOCKGUARD_APPROVAL_TEST") {
	case "approve":
		return approval.NewStaticApprover(true, "test-auto-approve")
	case "deny":
		return approval.NewStaticApprover(false, "test-auto-deny")
	}
	// Real approver: a DEDICATED Telegram bot (never the fleet's main bot). Both
	// env vars must be set; otherwise NO approver is wired and every gated call
	// fails closed (logged loud below).
	token := os.Getenv("NOCKGUARD_APPROVAL_BOT_TOKEN")
	chatID := os.Getenv("NOCKGUARD_APPROVAL_CHAT_ID")
	if token != "" && chatID != "" {
		timeout := 2 * time.Minute
		logger.Printf("Phase 5 approval gate ON — Telegram (dedicated bot), %s timeout, fail-safe deny", timeout)
		return approval.NewTelegramApprover(token, chatID, timeout)
	}
	logger.Printf("Phase 5 approval gate: no approver configured (set NOCKGUARD_APPROVAL_BOT_TOKEN + NOCKGUARD_APPROVAL_CHAT_ID); ALL gated calls fail CLOSED — both `ask` rules and legacy `require_approval` rules will be DENIED until an approver is wired")
	return nil
}

func main() {
	os.Exit(runCLI(os.Args[1:]))
}

func runCLI(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printUsage()
		return 0
	}

	if args[0] == "version" {
		fmt.Println("nockguard v0.1.0")
		return 0
	}

	if args[0] == "audit" {
		return runAudit(args[1:])
	}

	if args[0] == "policy" {
		return runPolicy(args[1:])
	}

	// `verify` is a first-class top-level alias for `audit verify`. The one-command
	// offline trail proof is the headline accountability artifact ("prove your
	// agent fleet's trail is intact and non-repudiable in one command"), so it gets
	// the verb a user reaches for directly: `nockguard verify --agent <name>`.
	if args[0] == "verify" {
		return runAudit(args)
	}

	if args[0] == "keygen" {
		return runKeygen(args[1:])
	}

	if args[0] == "init" {
		return runInit(args[1:])
	}

	if args[0] == "evidence" {
		return runEvidence(args[1:])
	}

	if args[0] == "trust" {
		return runTrust(args[1:])
	}

	if args[0] == "egress-proxy" {
		return runEgressProxy(args[1:])
	}

	if args[0] != "proxy" {
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", args[0])
		printUsage()
		return 1
	}

	var (
		upstreamCmd string
		agent       string
		policyPath  string
	)

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--upstream":
			if i+1 < len(args) {
				i++
				upstreamCmd = args[i]
			}
		case "--agent":
			if i+1 < len(args) {
				i++
				agent = args[i]
			}
		case "--policy":
			if i+1 < len(args) {
				i++
				policyPath = args[i]
			}
		}
	}

	if upstreamCmd == "" {
		fmt.Fprintln(os.Stderr, "error: --upstream is required")
		return 1
	}
	if agent == "" {
		fmt.Fprintln(os.Stderr, "error: --agent is required")
		return 1
	}
	if policyPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot determine home directory: %v\n", err)
			return 1
		}
		policyPath = home + "/.nockguard/policy.yaml"
	}

	engine, err := policy.Load(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading policy %s: %v\n", policyPath, err)
		return 1
	}

	// Fail-closed is correct but should never be a silent surprise: if the named
	// agent has neither its own policy nor a "default", every tool will be denied.
	// Warn loudly so the operator fixes the policy instead of debugging a deny-all.
	if !engine.HasPolicyFor(agent) {
		fmt.Fprintf(os.Stderr, "warning: no policy for agent %q and no \"default\" — ALL tools will be DENIED (fail-closed). Add an agent or \"default\" policy in %s.\n", agent, policyPath)
	}

	validator, err := engine.ValidatorFor(agent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error building input validator for agent %s: %v\n", agent, err)
		return 1
	}

	limiter, err := engine.LimiterFor(agent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error building rate limiter for agent %s: %v\n", agent, err)
		return 1
	}
	trustAccumulator, err := engine.TrustFor(agent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error building trust accumulator for agent %s: %v\n", agent, err)
		return 1
	}

	auditor, err := engine.AuditorFor(agent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening audit trail: %v\n", err)
		return 1
	}
	defer auditor.Close()

	forwarder, err := engine.Forwarder()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error configuring ops-log forwarder: %v\n", err)
		return 1
	}
	forwarder.Start()
	defer forwarder.Stop()

	logger := log.New(os.Stderr, "[nockguard] ", log.LstdFlags)
	upstream := parseCommand(upstreamCmd)

	p := proxy.NewStdioProxy(upstream, agent, engine, validator, limiter, auditor, forwarder, logger).
		WithTrust(trustAccumulator).
		WithApprover(buildApprover(logger))
	if err := p.Run(); err != nil {
		logger.Printf("proxy error: %v", err)
		return 1
	}
	return 0
}

func runPolicy(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: nockguard policy (propose | shadow-report) --agent <name> [--audit-dir <dir> | --audit <path>]")
		return 1
	}
	switch args[0] {
	case "propose":
		return runPolicyPropose(args[1:])
	case "shadow-report":
		return runPolicyShadowReport(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown policy command: %s\n", args[0])
		return 1
	}
}

func runPolicyPropose(args []string) int {
	agent, auditPath, ok := parsePolicyAuditArgs(args)
	if !ok {
		return 1
	}
	tools, err := policy.ProposeShadowFromAudit(agent, auditPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading audit trail: %v\n", err)
		return 1
	}
	type proposedAgentPolicy struct {
		Mode   string   `yaml:"mode"`
		Shadow []string `yaml:"shadow"`
	}
	out := struct {
		Agents map[string]proposedAgentPolicy `yaml:"agents"`
	}{
		Agents: map[string]proposedAgentPolicy{
			agent: {Mode: "allow", Shadow: tools},
		},
	}
	data, err := yaml.Marshal(out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error rendering proposal: %v\n", err)
		return 1
	}
	fmt.Print(string(data))
	return 0
}

func runPolicyShadowReport(args []string) int {
	agent, auditPath, ok := parsePolicyAuditArgs(args)
	if !ok {
		return 1
	}
	misses, err := policy.ShadowReportFromAudit(agent, auditPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading audit trail: %v\n", err)
		return 1
	}
	if len(misses) == 0 {
		fmt.Printf("0 would-deny entries for %s\n", agent)
		return 0
	}
	fmt.Printf("would-deny entries for %s:\n", agent)
	for _, miss := range misses {
		fmt.Printf("%s %d\n", miss.Tool, miss.Count)
	}
	return 0
}

func parsePolicyAuditArgs(args []string) (agent, auditPath string, ok bool) {
	var auditDir string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--agent":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --agent requires a value")
				return "", "", false
			}
			i++
			agent = args[i]
		case "--audit":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --audit requires a value")
				return "", "", false
			}
			i++
			auditPath = args[i]
		case "--audit-dir":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --audit-dir requires a value")
				return "", "", false
			}
			i++
			auditDir = args[i]
		default:
			fmt.Fprintf(os.Stderr, "error: unknown flag %q\n", args[i])
			return "", "", false
		}
	}
	if agent == "" {
		fmt.Fprintln(os.Stderr, "error: --agent is required")
		return "", "", false
	}
	if !policy.ValidAgentName(agent) {
		fmt.Fprintf(os.Stderr, "error: invalid agent name %q: only alphanumerics, hyphens, and dots are allowed\n", agent)
		return "", "", false
	}
	if auditPath != "" && auditDir != "" {
		fmt.Fprintln(os.Stderr, "error: provide only one of --audit or --audit-dir")
		return "", "", false
	}
	if auditPath == "" {
		if auditDir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: cannot determine home directory: %v\n", err)
				return "", "", false
			}
			auditDir = filepath.Join(home, filepath.Dir(policy.DefaultAuditPath))
		}
		basePath := filepath.Join(auditDir, filepath.Base(policy.DefaultAuditPath))
		auditPath = policy.AgentAuditPath(basePath, agent)
	}
	return agent, auditPath, true
}

func runEgressProxy(args []string) int {
	var (
		listen     string
		agent      string
		policyPath string
		auditPath  string
		enforce    bool
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--listen":
			if i+1 < len(args) {
				i++
				listen = args[i]
			}
		case "--agent":
			if i+1 < len(args) {
				i++
				agent = args[i]
			}
		case "--policy":
			if i+1 < len(args) {
				i++
				policyPath = args[i]
			}
		case "--audit":
			if i+1 < len(args) {
				i++
				auditPath = args[i]
			}
		case "--enforce":
			enforce = true
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
	engine, err := policy.Load(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading policy %s: %v\n", policyPath, err)
		return 1
	}
	if err := forwardhttp.ValidateConfig(listen, agent, engine); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if !engine.HasPolicyFor(agent) {
		fmt.Fprintf(os.Stderr, "warning: no policy for agent %q and no \"default\" — ALL egress hosts will audit as DENIED (observe-only). Add an agent or \"default\" policy in %s.\n", agent, policyPath)
	}

	var auditor *audit.Auditor
	if auditPath != "" {
		auditor, err = engine.AuditorAt(auditPath)
	} else {
		auditor, err = engine.AuditorFor(agent)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening audit trail: %v\n", err)
		return 1
	}
	defer auditor.Close()

	logger := log.New(os.Stderr, "[nockguard-egress] ", log.LstdFlags)
	mode := "observe-only"
	if enforce {
		mode = "enforce"
	}
	logger.Printf("starting HTTP/HTTPS egress proxy listen=%s agent=%s policy=%s mode=%s", listen, agent, policyPath, mode)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := forwardhttp.New(listen, agent, engine, auditor, logger).WithEnforce(enforce).Run(ctx); err != nil {
		logger.Printf("egress proxy error: %v", err)
		return 1
	}
	return 0
}

func parseCommand(cmd string) []string {
	return strings.Fields(cmd)
}

// runAudit handles `nockguard audit verify`. Supports two modes:
//
//   - Per-agent: `--agent <name>` derives both the audit file path
//     (<audit-dir>/<name>.audit.jsonl) and the public key env var
//     (NOCKGUARD_AGENT_<NAME>_ED25519_PUB) from the agent name alone.
//     Use --audit-dir to override the directory (default ~/.nockguard/logs).
//
//   - Global: `--key-env <ENV>` (HMAC) or `--ed25519-pub-env <ENV>` (Ed25519)
//     with an optional `--audit <path>` override. Backward-compatible with
//     the pre-Phase-5 flow.
//
// Exit 0 = chain intact, 2 = tampering detected, 1 = usage/setup error.
// verifyAllAgents verifies EVERY per-agent Ed25519 trail (<agent>.audit.jsonl)
// in the audit dir — the "prove the whole fleet is accountable in one command"
// path behind `nockguard verify --all`. Each trail is checked with that agent's
// own public key (NOCKGUARD_AGENT_<NAME>_ED25519_PUB). Exit 0 = all intact,
// 2 = any tampered, 1 = any trail it could not verify (missing/invalid key).
type verifyResult struct {
	Verdict         string `json:"verdict"`
	AuditPath       string `json:"audit_path,omitempty"`
	EntriesVerified int    `json:"entries_verified"`
	Error           string `json:"error,omitempty"`
}

type verifyAllResult struct {
	Verdict      string              `json:"verdict"`
	AuditDir     string              `json:"audit_dir"`
	Total        int                 `json:"total"`
	Intact       int                 `json:"intact"`
	Tampered     int                 `json:"tampered"`
	Unverifiable int                 `json:"unverifiable"`
	Trails       []verifyTrailResult `json:"trails"`
}

type verifyTrailResult struct {
	Agent           string `json:"agent"`
	Path            string `json:"path"`
	Status          string `json:"status"`
	EntriesVerified int    `json:"entries_verified,omitempty"`
	Error           string `json:"error,omitempty"`
}

func writeJSON(value any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(value)
}

func verifyAllAgents(auditDir string, jsonOutput bool) int {
	baseDir := auditDir
	if baseDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot determine home directory: %v\n", err)
			return 1
		}
		baseDir = filepath.Join(home, filepath.Dir(policy.DefaultAuditPath))
	}
	suffix := "." + filepath.Base(policy.DefaultAuditPath) // ".audit.jsonl"
	matches, err := filepath.Glob(filepath.Join(baseDir, "*"+suffix))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error scanning %s: %v\n", baseDir, err)
		return 1
	}
	if len(matches) == 0 {
		if jsonOutput {
			writeJSON(verifyAllResult{Verdict: "PROTECTED", AuditDir: baseDir})
		} else {
			fmt.Printf("No per-agent audit trails (*%s) found in %s\n", suffix, baseDir)
			fmt.Println("VERDICT: PROTECTED")
		}
		return 0
	}
	var intact, tampered, unverifiable int
	results := make([]verifyTrailResult, 0, len(matches))
	for _, path := range matches {
		agent := strings.TrimSuffix(filepath.Base(path), suffix)
		if agent == "" || !policy.ValidAgentName(agent) {
			if !jsonOutput {
				fmt.Printf("  [SKIP]   %-18s invalid agent name\n", agent)
			}
			results = append(results, verifyTrailResult{Agent: agent, Path: path, Status: "UNVERIFIABLE", Error: "invalid agent name"})
			unverifiable++
			continue
		}
		envName := policy.AgentPubKeyEnvName(agent)
		pubHex := os.Getenv(envName)
		if pubHex == "" {
			msg := envName + " not set"
			if !jsonOutput {
				fmt.Printf("  [NO KEY] %-18s %s\n", agent, msg)
			}
			results = append(results, verifyTrailResult{Agent: agent, Path: path, Status: "UNVERIFIABLE", Error: msg})
			unverifiable++
			continue
		}
		pub, perr := audit.PublicKeyFromHex(pubHex)
		if perr != nil {
			if !jsonOutput {
				fmt.Printf("  [NO KEY] %-18s %v\n", agent, perr)
			}
			results = append(results, verifyTrailResult{Agent: agent, Path: path, Status: "UNVERIFIABLE", Error: perr.Error()})
			unverifiable++
			continue
		}
		n, verr := audit.VerifyEd25519(path, pub)
		if verr != nil {
			if !jsonOutput {
				fmt.Printf("  [TAMPER] %-18s %v\n", agent, verr)
			}
			results = append(results, verifyTrailResult{Agent: agent, Path: path, Status: "TAMPERED", EntriesVerified: n, Error: verr.Error()})
			tampered++
			continue
		}
		if !jsonOutput {
			fmt.Printf("  [OK]     %-18s %d entries, chain intact\n", agent, n)
		}
		results = append(results, verifyTrailResult{Agent: agent, Path: path, Status: "PROTECTED", EntriesVerified: n})
		intact++
	}
	verdict := "PROTECTED"
	if tampered > 0 {
		verdict = "TAMPERED"
	} else if unverifiable > 0 {
		verdict = "UNVERIFIABLE"
	}
	if jsonOutput {
		writeJSON(verifyAllResult{
			Verdict:      verdict,
			AuditDir:     baseDir,
			Total:        len(matches),
			Intact:       intact,
			Tampered:     tampered,
			Unverifiable: unverifiable,
			Trails:       results,
		})
	} else {
		fmt.Printf("\n%d trails in %s — %d intact, %d tampered, %d unverifiable\n", len(matches), baseDir, intact, tampered, unverifiable)
		fmt.Printf("VERDICT: %s\n", verdict)
	}
	switch {
	case tampered > 0:
		return 2
	case unverifiable > 0:
		return 1
	default:
		return 0
	}
}

func runAudit(args []string) int {
	if len(args) == 0 || args[0] != "verify" {
		fmt.Fprintln(os.Stderr, "usage: nockguard audit verify (--agent <name> | --key-env <ENV> | --ed25519-pub-env <ENV>) [--audit <path>] [--audit-dir <dir>]")
		return 1
	}
	var auditPath, auditDir, agentName, keyEnv, pubEnv string
	allMode := false
	jsonOutput := false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--all":
			allMode = true
		case "--json":
			jsonOutput = true
		case "--audit":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --audit requires a value")
				return 1
			}
			i++
			auditPath = args[i]
		case "--audit-dir":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --audit-dir requires a value")
				return 1
			}
			i++
			auditDir = args[i]
		case "--agent":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --agent requires a value")
				return 1
			}
			i++
			agentName = args[i]
		case "--key-env":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --key-env requires a value")
				return 1
			}
			i++
			keyEnv = args[i]
		case "--ed25519-pub-env":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --ed25519-pub-env requires a value")
				return 1
			}
			i++
			pubEnv = args[i]
		default:
			fmt.Fprintf(os.Stderr, "error: unknown flag %q\n", args[i])
			return 1
		}
	}

	// --all verifies EVERY per-agent trail in one command ("prove the whole fleet
	// is accountable") and short-circuits the single-trail modes below.
	if allMode {
		return verifyAllAgents(auditDir, jsonOutput)
	}

	// Exactly one verification mode must be specified.
	modeCount := 0
	if agentName != "" {
		modeCount++
	}
	if keyEnv != "" {
		modeCount++
	}
	if pubEnv != "" {
		modeCount++
	}
	if modeCount != 1 {
		fmt.Fprintln(os.Stderr, "error: provide exactly one of --agent <name>, --key-env <ENV>, or --ed25519-pub-env <ENV>")
		return 1
	}

	// Per-agent mode: derive path and pub-key env from agent name.
	if agentName != "" {
		if !policy.ValidAgentName(agentName) {
			fmt.Fprintf(os.Stderr, "error: invalid agent name %q: only alphanumerics, hyphens, and dots are allowed\n", agentName)
			return 1
		}
		baseDir := auditDir
		if baseDir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: cannot determine home directory: %v\n", err)
				return 1
			}
			baseDir = filepath.Join(home, filepath.Dir(policy.DefaultAuditPath))
		}
		baseName := filepath.Base(policy.DefaultAuditPath)
		basePath := filepath.Join(baseDir, baseName)
		auditPath = policy.AgentAuditPath(basePath, agentName)
		pubEnv = policy.AgentPubKeyEnvName(agentName)
	}

	if auditPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot determine home directory: %v\n", err)
			return 1
		}
		auditPath = filepath.Join(home, policy.DefaultAuditPath)
	}
	if (keyEnv == "") == (pubEnv == "") {
		fmt.Fprintln(os.Stderr, "error: provide --agent <name>, --key-env <ENV> (HMAC), or --ed25519-pub-env <ENV> (Ed25519 public key)")
		return 1
	}

	var (
		n   int
		err error
	)
	if pubEnv != "" {
		pubHex := os.Getenv(pubEnv)
		if pubHex == "" {
			fmt.Fprintf(os.Stderr, "error: %s is not set in the environment\n", pubEnv)
			return 1
		}
		pub, perr := audit.PublicKeyFromHex(pubHex)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", perr)
			return 1
		}
		n, err = audit.VerifyEd25519(auditPath, pub)
	} else {
		key := os.Getenv(keyEnv)
		if key == "" {
			fmt.Fprintf(os.Stderr, "error: %s is not set in the environment\n", keyEnv)
			return 1
		}
		n, err = audit.Verify(auditPath, []byte(key))
	}

	if err != nil {
		if jsonOutput {
			writeJSON(verifyResult{Verdict: "TAMPERED", AuditPath: auditPath, EntriesVerified: n, Error: err.Error()})
		} else {
			fmt.Fprintf(os.Stderr, "TAMPER DETECTED — %s (verified %d before the break): %v\n", auditPath, n, err)
		}
		return 2
	}
	if jsonOutput {
		writeJSON(verifyResult{Verdict: "PROTECTED", AuditPath: auditPath, EntriesVerified: n})
	} else {
		fmt.Printf("OK — %d entries verified, hash chain intact: %s\n", n, auditPath)
		fmt.Println("VERDICT: PROTECTED")
	}
	return 0
}

// runEvidence handles `nockguard evidence` — it builds a compliance-evidence
// pack from one or more signed audit trails, mapping their entries onto a
// framework's controls and rendering an Integrity Attestation produced by the
// SAME verifier as `audit verify`. The attestation fails LOUD: a broken chain
// renders a FAILED banner and the command exits 2, but the pack is still written
// so a reviewer sees exactly what broke.
//
// Verification mode (exactly one):
//   - --agent <name>: derives the audit file (<audit-dir>/<name>.audit.jsonl)
//     and the Ed25519 public-key env var (NOCKGUARD_AGENT_<NAME>_ED25519_PUB).
//   - --ed25519-pub-env <ENV>: explicit Ed25519 public-key env var, with --audit.
//   - --key-env <ENV>: HMAC key env var (tamper-evident), with --audit.
//
// Exit 0 = chain intact, 2 = chain broken (pack still produced), 1 = setup error.
func runEvidence(args []string) int {
	var (
		framework = "soc2"
		auditPath string
		auditDir  string
		agentName string
		keyEnv    string
		pubEnv    string
		fromStr   string
		toStr     string
		format    = "html"
		outPath   string
	)
	needsValue := func(i int, name string) string {
		if i+1 >= len(args) {
			fmt.Fprintf(os.Stderr, "error: %s requires a value\n", name)
			return ""
		}
		return args[i+1]
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--framework":
			framework = strings.ToLower(needsValue(i, "--framework"))
			if framework == "" {
				return 1
			}
			i++
		case "--audit":
			auditPath = needsValue(i, "--audit")
			if auditPath == "" {
				return 1
			}
			i++
		case "--audit-dir":
			auditDir = needsValue(i, "--audit-dir")
			if auditDir == "" {
				return 1
			}
			i++
		case "--agent":
			agentName = needsValue(i, "--agent")
			if agentName == "" {
				return 1
			}
			i++
		case "--key-env":
			keyEnv = needsValue(i, "--key-env")
			if keyEnv == "" {
				return 1
			}
			i++
		case "--ed25519-pub-env":
			pubEnv = needsValue(i, "--ed25519-pub-env")
			if pubEnv == "" {
				return 1
			}
			i++
		case "--from":
			fromStr = needsValue(i, "--from")
			if fromStr == "" {
				return 1
			}
			i++
		case "--to":
			toStr = needsValue(i, "--to")
			if toStr == "" {
				return 1
			}
			i++
		case "--format":
			format = strings.ToLower(needsValue(i, "--format"))
			if format == "" {
				return 1
			}
			i++
		case "-o", "--output":
			outPath = needsValue(i, args[i])
			if outPath == "" {
				return 1
			}
			i++
		default:
			fmt.Fprintf(os.Stderr, "error: unknown flag %q\n", args[i])
			return 1
		}
	}

	if format != "html" && format != "json" {
		fmt.Fprintf(os.Stderr, "error: --format must be html or json (got %q)\n", format)
		return 1
	}
	fw := evidence.Framework(framework)
	if !evidence.KnownFramework(fw) {
		fmt.Fprintf(os.Stderr, "error: unknown framework %q (supported: soc2; gdpr, pci, hipaa are stubs)\n", framework)
		return 1
	}

	// Resolve the audit file path and verification key. --agent derives both the
	// path and the Ed25519 pub-key env, mirroring `audit verify --agent`.
	if agentName != "" {
		if !policy.ValidAgentName(agentName) {
			fmt.Fprintf(os.Stderr, "error: invalid agent name %q: only alphanumerics, hyphens, and dots are allowed\n", agentName)
			return 1
		}
		baseDir := auditDir
		if baseDir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: cannot determine home directory: %v\n", err)
				return 1
			}
			baseDir = filepath.Join(home, filepath.Dir(policy.DefaultAuditPath))
		}
		basePath := filepath.Join(baseDir, filepath.Base(policy.DefaultAuditPath))
		auditPath = policy.AgentAuditPath(basePath, agentName)
		if pubEnv == "" && keyEnv == "" {
			pubEnv = policy.AgentPubKeyEnvName(agentName)
		}
	}
	if auditPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot determine home directory: %v\n", err)
			return 1
		}
		auditPath = filepath.Join(home, policy.DefaultAuditPath)
	}

	// Exactly one key source.
	if (keyEnv == "") == (pubEnv == "") {
		fmt.Fprintln(os.Stderr, "error: provide exactly one verification key: --agent <name>, --ed25519-pub-env <ENV>, or --key-env <ENV>")
		return 1
	}

	opts := evidence.PackOptions{
		Framework:  fw,
		AuditFiles: []string{auditPath},
		Agent:      agentName,
	}
	if pubEnv != "" {
		pubHex := os.Getenv(pubEnv)
		if pubHex == "" {
			fmt.Fprintf(os.Stderr, "error: %s is not set in the environment\n", pubEnv)
			return 1
		}
		opts.Ed25519PubHex = pubHex
	} else {
		key := os.Getenv(keyEnv)
		if key == "" {
			fmt.Fprintf(os.Stderr, "error: %s is not set in the environment\n", keyEnv)
			return 1
		}
		opts.HMACKey = []byte(key)
	}
	if fromStr != "" {
		from, err := parseDateFlag(fromStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: --from: %v\n", err)
			return 1
		}
		opts.From = from
	}
	if toStr != "" {
		to, err := parseDateFlag(toStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: --to: %v\n", err)
			return 1
		}
		opts.To = to
	}

	pack, err := evidence.BuildPack(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error building evidence pack: %v\n", err)
		return 1
	}

	var rendered []byte
	if format == "json" {
		rendered, err = evidence.RenderJSON(pack)
	} else {
		rendered, err = evidence.RenderHTML(pack)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error rendering evidence pack: %v\n", err)
		return 1
	}

	if outPath != "" {
		if werr := os.WriteFile(outPath, rendered, 0o644); werr != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", outPath, werr)
			return 1
		}
		dest := outPath
		fmt.Fprintf(os.Stderr, "Wrote %s evidence pack: %s\n", strings.ToUpper(format), dest)
	} else {
		os.Stdout.Write(rendered)
		if format == "html" {
			fmt.Fprintln(os.Stdout)
		}
	}

	// Fail LOUD on a broken chain: report it to stderr and exit 2, mirroring
	// `audit verify`. The pack is already written/printed so the failure is
	// visible, not hidden behind a non-zero exit.
	if !pack.Verification.ChainIntact {
		fmt.Fprintf(os.Stderr, "TAMPER DETECTED — the audit chain backing this evidence is BROKEN (%d entries verified before the break): %s\n", pack.Verification.EntriesVerified, pack.Verification.Detail)
		return 2
	}
	fmt.Fprintf(os.Stderr, "OK — %d entries verified, chain intact; evidence pack reflects a trustworthy trail.\n", pack.Verification.EntriesVerified)
	return 0
}

// parseDateFlag accepts either a date (2006-01-02) or a full RFC3339 timestamp.
// A bare date is interpreted at UTC midnight.
func parseDateFlag(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("date must be YYYY-MM-DD or RFC3339, got %q", s)
	}
	return t.UTC(), nil
}

func runTrust(args []string) int {
	if len(args) == 0 || args[0] != "show" {
		fmt.Fprintln(os.Stderr, "usage: nockguard trust show --agent <name>")
		return 1
	}
	var agentName string
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--agent":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --agent requires a value")
				return 1
			}
			i++
			agentName = args[i]
		default:
			fmt.Fprintf(os.Stderr, "error: unknown flag %q\n", args[i])
			return 1
		}
	}
	if !policy.ValidAgentName(agentName) {
		fmt.Fprintf(os.Stderr, "error: invalid agent name %q: only alphanumerics, hyphens, and dots are allowed\n", agentName)
		return 1
	}
	acc, err := trust.New(trust.Config{Enabled: true, Agent: agentName})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading trust score for agent %s: %v\n", agentName, err)
		return 1
	}
	score := acc.Score()
	fmt.Printf("agent: %s\n", agentName)
	fmt.Printf("score: %.3f\n", score)
	fmt.Printf("tier: %s\n", trust.TierFor(score))
	fmt.Printf("effective_multiplier: %.1fx\n", trust.MultiplierFor(score))
	return 0
}

// runKeygen generates a fresh Ed25519 keypair for non-repudiable audit signing.
// With --agent <name> it emits agent-namespaced variable names
// (NOCKGUARD_AGENT_<UPPER>_ED25519_KEY / _PUB) so each agent can hold its own
// signing identity. Without --agent it emits the legacy global variable names.
func runKeygen(args []string) int {
	var agentName string
	for i := 0; i < len(args); i++ {
		if args[i] == "--agent" {
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --agent requires a value")
				return 1
			}
			i++
			agentName = args[i]
			if !policy.ValidAgentName(agentName) {
				fmt.Fprintf(os.Stderr, "error: invalid agent name %q: only alphanumerics, hyphens, and dots are allowed\n", agentName)
				return 1
			}
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen failed: %v\n", err)
		return 1
	}
	if agentName != "" {
		keyEnv := policy.AgentKeyEnvName(agentName)
		pubEnv := policy.AgentPubKeyEnvName(agentName)
		fmt.Printf("# Ed25519 keypair for agent: %s\n", agentName)
		fmt.Printf("# PRIVATE seed — secret. Set in the proxy environment; never commit.\n")
		fmt.Printf("%s=%s\n\n", keyEnv, hex.EncodeToString(priv.Seed()))
		fmt.Printf("# PUBLIC key — share with verifiers. Cannot produce signatures.\n")
		fmt.Printf("%s=%s\n", pubEnv, hex.EncodeToString(pub))
	} else {
		fmt.Printf("# Ed25519 audit signing keypair\n")
		fmt.Printf("# PRIVATE seed — secret. Set as the signing env (sign_ed25519_key_env); never commit.\n")
		fmt.Printf("NOCKGUARD_AUDIT_ED25519_KEY=%s\n\n", hex.EncodeToString(priv.Seed()))
		fmt.Printf("# PUBLIC key — share with verifiers. Cannot forge entries.\n")
		fmt.Printf("NOCKGUARD_AUDIT_ED25519_PUB=%s\n", hex.EncodeToString(pub))
	}
	return 0
}

// runInit handles `nockguard init` — it scaffolds a sensible, default-deny
// starter policy so a new user is guarded in seconds instead of hand-writing
// YAML. It never overwrites an existing policy without --force.
func runInit(args []string) int {
	var policyPath string
	force := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--policy":
			if i+1 < len(args) {
				i++
				policyPath = args[i]
			}
		case "--force":
			force = true
		}
	}
	if policyPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot determine home directory: %v\n", err)
			return 1
		}
		policyPath = filepath.Join(home, ".nockguard", "policy.yaml")
	}

	written, err := policy.WriteStarter(policyPath, force)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if !written {
		return 0
	}
	fmt.Printf("Wrote starter policy: %s\n\n", policyPath)
	fmt.Println("Next:")
	fmt.Printf("  1. Edit %s — rename the agent and set its allow/deny lists.\n", policyPath)
	fmt.Println("  2. Run the firewall in front of your MCP server:")
	fmt.Printf("     nockguard proxy --upstream \"<your mcp server cmd>\" --agent <name> --policy %s\n", policyPath)
	return 0
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `nockguard — MCP firewall for AI agent fleets

Usage:
  nockguard init [--policy <path>] [--force]
  nockguard proxy --upstream <command> --agent <name> [--policy <path>]
  nockguard egress-proxy --listen <addr> --agent <name> --policy <path> [--audit <path>] [--enforce]
  nockguard verify (--all | --agent <name> | --key-env <ENV> | --ed25519-pub-env <ENV>) [--audit <path>] [--audit-dir <dir>]
  nockguard policy propose --agent <name> [--audit <path>] [--audit-dir <dir>]
  nockguard policy shadow-report --agent <name> [--audit <path>] [--audit-dir <dir>]
  nockguard trust show --agent <name>
  nockguard audit verify ...   # same as 'nockguard verify' (the audit-namespaced form)
  nockguard evidence --framework soc2 (--agent <name> | --ed25519-pub-env <ENV> | --key-env <ENV>) [--audit <path>] [--audit-dir <dir>] [--from <date>] [--to <date>] [--format html|json] [-o <file>]
  nockguard keygen [--agent <name>]
  nockguard version

Options:
  --upstream         MCP server command to proxy (required)
  --listen           HTTP/HTTPS forward-proxy listen address (for: egress-proxy)
  --agent            Agent identity for policy lookup / per-agent keypair flow
  --policy           Path to policy YAML (default: ~/.nockguard/policy.yaml)
  --enforce          Block denied egress hosts (returns 403); default is observe-only (logs but allows)
  --force            Overwrite an existing policy (for: init)
  --key-env          Env var holding the HMAC signing key (tamper-evident verify)
  --ed25519-pub-env  Env var holding the hex Ed25519 public key (non-repudiable verify)
  --audit            Path to the audit JSONL (default: ~/.nockguard/logs/audit.jsonl)
  --audit-dir        Directory holding per-agent audit files (for: audit verify / evidence --agent)
  --framework        Compliance framework to map against (for: evidence) — soc2 (gdpr/pci/hipaa are stubs)
  --from / --to      Inclusive date filter for evidence entries (YYYY-MM-DD or RFC3339)
  --format           Evidence output format: html (default) or json
  -o, --output       Write the evidence pack to a file instead of stdout

Per-agent signing:
  Each agent gets its own Ed25519 keypair. The trail is signed with the agent's
  private key and written to <agent>.audit.jsonl, verifiable with only that
  agent's public key — non-repudiable: proves which agent did what.

Evidence packs:
  `+"`nockguard evidence`"+` reads the SAME signed trail `+"`audit verify`"+` checks, maps its
  entries onto a framework's controls (SOC 2 today), and renders an Integrity
  Attestation. A broken chain renders a prominent FAILED banner and exits 2 — the
  pack is still produced so the break is visible, never silently dropped.

Examples:
  nockguard init                                        # scaffold a default-deny starter policy
  nockguard proxy --upstream "npx mcp-server-nockcc" --agent kit --policy policy.yaml
  nockguard egress-proxy --listen 127.0.0.1:8899 --agent kit --policy egress.yaml
  nockguard keygen --agent kit                          # generate per-agent keypair
  nockguard verify --agent kit                          # prove kit's trail is intact + non-repudiable (exit 0 = clean, 2 = tampered)
  nockguard verify --all                                # prove EVERY per-agent trail in ~/.nockguard/logs in one command
  nockguard policy propose --agent kit                   # derive a shadow allowlist from kit's observed allowed tools
  nockguard policy shadow-report --agent kit             # count shadow would-deny misses by tool
  nockguard evidence --framework soc2 --agent kit -o kit-soc2.html   # SOC2 pack for kit's signed trail
  nockguard keygen                                      # generate global keypair (legacy)
  nockguard audit verify --ed25519-pub-env NOCKGUARD_AUDIT_ED25519_PUB  # verify global trail`)
}
