package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nocktechnologies/nockguard/internal/approval"
	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/evidence"
	"github.com/nocktechnologies/nockguard/internal/policy"
	"github.com/nocktechnologies/nockguard/internal/proxy"
	"github.com/nocktechnologies/nockguard/internal/trust"
)

// buildApprover wires the Phase 5 approval gate. For now: a deterministic test
// seam (NOCKGUARD_APPROVAL_TEST=approve|deny) used by e2e tests, otherwise no
// approver (nil). nil preserves the legacy require_approval behavior; the new
// Ask verdict fails closed without an approver.
func buildApprover(logger *log.Logger) approval.Approver {
	switch os.Getenv("NOCKGUARD_APPROVAL_TEST") {
	case "approve":
		return approval.NewStaticApprover(true, "test-auto-approve")
	case "deny":
		return approval.NewStaticApprover(false, "test-auto-deny")
	}
	// Real approver: a DEDICATED Telegram bot (never the fleet's main bot). Both
	// env vars must be set; otherwise the gate is un-enforced (logged loud).
	token := os.Getenv("NOCKGUARD_APPROVAL_BOT_TOKEN")
	chatID := os.Getenv("NOCKGUARD_APPROVAL_CHAT_ID")
	if token != "" && chatID != "" {
		timeout := 2 * time.Minute
		logger.Printf("Phase 5 approval gate ON — Telegram (dedicated bot), %s timeout, fail-safe deny", timeout)
		return approval.NewTelegramApprover(token, chatID, timeout)
	}
	logger.Printf("Phase 5 approval gate: no approver configured (set NOCKGUARD_APPROVAL_BOT_TOKEN + NOCKGUARD_APPROVAL_CHAT_ID); ask rules fail closed, legacy require_approval rules are un-enforced")
	return nil
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printUsage()
		os.Exit(0)
	}

	if args[0] == "version" {
		fmt.Println("nockguard v0.1.0")
		os.Exit(0)
	}

	if args[0] == "audit" {
		runAudit(args[1:])
		return
	}

	if args[0] == "keygen" {
		runKeygen(args[1:])
		return
	}

	if args[0] == "init" {
		runInit(args[1:])
		return
	}

	if args[0] == "evidence" {
		runEvidence(args[1:])
		return
	}

	if args[0] == "trust" {
		runTrust(args[1:])
		return
	}

	if args[0] != "proxy" {
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", args[0])
		printUsage()
		os.Exit(1)
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
		os.Exit(1)
	}
	if agent == "" {
		fmt.Fprintln(os.Stderr, "error: --agent is required")
		os.Exit(1)
	}
	if policyPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot determine home directory: %v\n", err)
			os.Exit(1)
		}
		policyPath = home + "/.nockguard/policy.yaml"
	}

	engine, err := policy.Load(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading policy %s: %v\n", policyPath, err)
		os.Exit(1)
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
		os.Exit(1)
	}

	limiter, err := engine.LimiterFor(agent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error building rate limiter for agent %s: %v\n", agent, err)
		os.Exit(1)
	}
	trustAccumulator, err := engine.TrustFor(agent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error building trust accumulator for agent %s: %v\n", agent, err)
		os.Exit(1)
	}

	auditor, err := engine.AuditorFor(agent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening audit trail: %v\n", err)
		os.Exit(1)
	}
	defer auditor.Close()

	forwarder, err := engine.Forwarder()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error configuring ops-log forwarder: %v\n", err)
		os.Exit(1)
	}
	forwarder.Start()
	defer forwarder.Stop()

	logger := log.New(os.Stderr, "[nockguard] ", log.LstdFlags)
	upstream := parseCommand(upstreamCmd)

	p := proxy.NewStdioProxy(upstream, agent, engine, validator, limiter, auditor, forwarder, logger).
		WithTrust(trustAccumulator).
		WithApprover(buildApprover(logger))
	if err := p.Run(); err != nil {
		logger.Fatalf("proxy error: %v", err)
	}
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
func runAudit(args []string) {
	if len(args) == 0 || args[0] != "verify" {
		fmt.Fprintln(os.Stderr, "usage: nockguard audit verify (--agent <name> | --key-env <ENV> | --ed25519-pub-env <ENV>) [--audit <path>] [--audit-dir <dir>]")
		os.Exit(1)
	}
	var auditPath, auditDir, agentName, keyEnv, pubEnv string
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--audit":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --audit requires a value")
				os.Exit(1)
			}
			i++
			auditPath = args[i]
		case "--audit-dir":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --audit-dir requires a value")
				os.Exit(1)
			}
			i++
			auditDir = args[i]
		case "--agent":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --agent requires a value")
				os.Exit(1)
			}
			i++
			agentName = args[i]
		case "--key-env":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --key-env requires a value")
				os.Exit(1)
			}
			i++
			keyEnv = args[i]
		case "--ed25519-pub-env":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --ed25519-pub-env requires a value")
				os.Exit(1)
			}
			i++
			pubEnv = args[i]
		}
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
		os.Exit(1)
	}

	// Per-agent mode: derive path and pub-key env from agent name.
	if agentName != "" {
		if !policy.ValidAgentName(agentName) {
			fmt.Fprintf(os.Stderr, "error: invalid agent name %q: only alphanumerics, hyphens, and dots are allowed\n", agentName)
			os.Exit(1)
		}
		baseDir := auditDir
		if baseDir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: cannot determine home directory: %v\n", err)
				os.Exit(1)
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
			os.Exit(1)
		}
		auditPath = filepath.Join(home, policy.DefaultAuditPath)
	}
	if (keyEnv == "") == (pubEnv == "") {
		fmt.Fprintln(os.Stderr, "error: provide --agent <name>, --key-env <ENV> (HMAC), or --ed25519-pub-env <ENV> (Ed25519 public key)")
		os.Exit(1)
	}

	var (
		n   int
		err error
	)
	if pubEnv != "" {
		pubHex := os.Getenv(pubEnv)
		if pubHex == "" {
			fmt.Fprintf(os.Stderr, "error: %s is not set in the environment\n", pubEnv)
			os.Exit(1)
		}
		pub, perr := audit.PublicKeyFromHex(pubHex)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", perr)
			os.Exit(1)
		}
		n, err = audit.VerifyEd25519(auditPath, pub)
	} else {
		key := os.Getenv(keyEnv)
		if key == "" {
			fmt.Fprintf(os.Stderr, "error: %s is not set in the environment\n", keyEnv)
			os.Exit(1)
		}
		n, err = audit.Verify(auditPath, []byte(key))
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "TAMPER DETECTED — %s (verified %d before the break): %v\n", auditPath, n, err)
		os.Exit(2)
	}
	fmt.Printf("OK — %d entries verified, hash chain intact: %s\n", n, auditPath)
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
func runEvidence(args []string) {
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
			os.Exit(1)
		}
		return args[i+1]
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--framework":
			framework = strings.ToLower(needsValue(i, "--framework"))
			i++
		case "--audit":
			auditPath = needsValue(i, "--audit")
			i++
		case "--audit-dir":
			auditDir = needsValue(i, "--audit-dir")
			i++
		case "--agent":
			agentName = needsValue(i, "--agent")
			i++
		case "--key-env":
			keyEnv = needsValue(i, "--key-env")
			i++
		case "--ed25519-pub-env":
			pubEnv = needsValue(i, "--ed25519-pub-env")
			i++
		case "--from":
			fromStr = needsValue(i, "--from")
			i++
		case "--to":
			toStr = needsValue(i, "--to")
			i++
		case "--format":
			format = strings.ToLower(needsValue(i, "--format"))
			i++
		case "-o", "--output":
			outPath = needsValue(i, args[i])
			i++
		default:
			fmt.Fprintf(os.Stderr, "error: unknown flag %q\n", args[i])
			os.Exit(1)
		}
	}

	if format != "html" && format != "json" {
		fmt.Fprintf(os.Stderr, "error: --format must be html or json (got %q)\n", format)
		os.Exit(1)
	}
	fw := evidence.Framework(framework)
	if !evidence.KnownFramework(fw) {
		fmt.Fprintf(os.Stderr, "error: unknown framework %q (supported: soc2; gdpr, pci, hipaa are stubs)\n", framework)
		os.Exit(1)
	}

	// Resolve the audit file path and verification key. --agent derives both the
	// path and the Ed25519 pub-key env, mirroring `audit verify --agent`.
	if agentName != "" {
		if !policy.ValidAgentName(agentName) {
			fmt.Fprintf(os.Stderr, "error: invalid agent name %q: only alphanumerics, hyphens, and dots are allowed\n", agentName)
			os.Exit(1)
		}
		baseDir := auditDir
		if baseDir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: cannot determine home directory: %v\n", err)
				os.Exit(1)
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
			os.Exit(1)
		}
		auditPath = filepath.Join(home, policy.DefaultAuditPath)
	}

	// Exactly one key source.
	if (keyEnv == "") == (pubEnv == "") {
		fmt.Fprintln(os.Stderr, "error: provide exactly one verification key: --agent <name>, --ed25519-pub-env <ENV>, or --key-env <ENV>")
		os.Exit(1)
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
			os.Exit(1)
		}
		opts.Ed25519PubHex = pubHex
	} else {
		key := os.Getenv(keyEnv)
		if key == "" {
			fmt.Fprintf(os.Stderr, "error: %s is not set in the environment\n", keyEnv)
			os.Exit(1)
		}
		opts.HMACKey = []byte(key)
	}
	if fromStr != "" {
		from, err := parseDateFlag(fromStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: --from: %v\n", err)
			os.Exit(1)
		}
		opts.From = from
	}
	if toStr != "" {
		to, err := parseDateFlag(toStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: --to: %v\n", err)
			os.Exit(1)
		}
		opts.To = to
	}

	pack, err := evidence.BuildPack(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error building evidence pack: %v\n", err)
		os.Exit(1)
	}

	var rendered []byte
	if format == "json" {
		rendered, err = evidence.RenderJSON(pack)
	} else {
		rendered, err = evidence.RenderHTML(pack)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error rendering evidence pack: %v\n", err)
		os.Exit(1)
	}

	if outPath != "" {
		if werr := os.WriteFile(outPath, rendered, 0o644); werr != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", outPath, werr)
			os.Exit(1)
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
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "OK — %d entries verified, chain intact; evidence pack reflects a trustworthy trail.\n", pack.Verification.EntriesVerified)
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

func runTrust(args []string) {
	if len(args) == 0 || args[0] != "show" {
		fmt.Fprintln(os.Stderr, "usage: nockguard trust show --agent <name>")
		os.Exit(1)
	}
	var agentName string
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--agent":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --agent requires a value")
				os.Exit(1)
			}
			i++
			agentName = args[i]
		default:
			fmt.Fprintf(os.Stderr, "error: unknown flag %q\n", args[i])
			os.Exit(1)
		}
	}
	if !policy.ValidAgentName(agentName) {
		fmt.Fprintf(os.Stderr, "error: invalid agent name %q: only alphanumerics, hyphens, and dots are allowed\n", agentName)
		os.Exit(1)
	}
	acc, err := trust.New(trust.Config{Enabled: true, Agent: agentName})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading trust score for agent %s: %v\n", agentName, err)
		os.Exit(1)
	}
	score := acc.Score()
	fmt.Printf("agent: %s\n", agentName)
	fmt.Printf("score: %.3f\n", score)
	fmt.Printf("tier: %s\n", trust.TierFor(score))
	fmt.Printf("effective_multiplier: %.1fx\n", trust.MultiplierFor(score))
}

// runKeygen generates a fresh Ed25519 keypair for non-repudiable audit signing.
// With --agent <name> it emits agent-namespaced variable names
// (NOCKGUARD_AGENT_<UPPER>_ED25519_KEY / _PUB) so each agent can hold its own
// signing identity. Without --agent it emits the legacy global variable names.
func runKeygen(args []string) {
	var agentName string
	for i := 0; i < len(args); i++ {
		if args[i] == "--agent" {
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --agent requires a value")
				os.Exit(1)
			}
			i++
			agentName = args[i]
			if !policy.ValidAgentName(agentName) {
				fmt.Fprintf(os.Stderr, "error: invalid agent name %q: only alphanumerics, hyphens, and dots are allowed\n", agentName)
				os.Exit(1)
			}
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen failed: %v\n", err)
		os.Exit(1)
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
}

// runInit handles `nockguard init` — it scaffolds a sensible, default-deny
// starter policy so a new user is guarded in seconds instead of hand-writing
// YAML. It never overwrites an existing policy without --force.
func runInit(args []string) {
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
			os.Exit(1)
		}
		policyPath = filepath.Join(home, ".nockguard", "policy.yaml")
	}

	written, err := policy.WriteStarter(policyPath, force)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if !written {
		return
	}
	fmt.Printf("Wrote starter policy: %s\n\n", policyPath)
	fmt.Println("Next:")
	fmt.Printf("  1. Edit %s — rename the agent and set its allow/deny lists.\n", policyPath)
	fmt.Println("  2. Run the firewall in front of your MCP server:")
	fmt.Printf("     nockguard proxy --upstream \"<your mcp server cmd>\" --agent <name> --policy %s\n", policyPath)
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `nockguard — MCP firewall for AI agent fleets

Usage:
  nockguard init [--policy <path>] [--force]
  nockguard proxy --upstream <command> --agent <name> [--policy <path>]
  nockguard trust show --agent <name>
  nockguard audit verify (--agent <name> | --key-env <ENV> | --ed25519-pub-env <ENV>) [--audit <path>] [--audit-dir <dir>]
  nockguard evidence --framework soc2 (--agent <name> | --ed25519-pub-env <ENV> | --key-env <ENV>) [--audit <path>] [--audit-dir <dir>] [--from <date>] [--to <date>] [--format html|json] [-o <file>]
  nockguard keygen [--agent <name>]
  nockguard version

Options:
  --upstream         MCP server command to proxy (required)
  --agent            Agent identity for policy lookup / per-agent keypair flow
  --policy           Path to policy YAML (default: ~/.nockguard/policy.yaml)
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
  nockguard keygen --agent kit                          # generate per-agent keypair
  nockguard audit verify --agent kit                    # verify kit's trail (reads NOCKGUARD_AGENT_KIT_ED25519_PUB)
  nockguard evidence --framework soc2 --agent kit -o kit-soc2.html   # SOC2 pack for kit's signed trail
  nockguard keygen                                      # generate global keypair (legacy)
  nockguard audit verify --ed25519-pub-env NOCKGUARD_AUDIT_ED25519_PUB  # verify global trail`)
}
