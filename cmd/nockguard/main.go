package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
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
	"github.com/nocktechnologies/nockguard/internal/proxy/mcphttp"
	"github.com/nocktechnologies/nockguard/internal/sessionverify"
	"github.com/nocktechnologies/nockguard/internal/trust"
	"gopkg.in/yaml.v3"
)

// buildApprover wires the Phase 5 approval gate. For now: a deterministic test
// seam (NOCKGUARD_APPROVAL_TEST=approve|deny) used by e2e tests, otherwise no
// approver (nil). With nil, BOTH native `ask` rules and legacy
// `require_approval` rules fail CLOSED — a covered call is denied, never
// forwarded (N8328: require_approval used to fail open here).
func buildApprover(logger *log.Logger) approval.Approver {
	switch os.Getenv(approval.EnvTestSeam) {
	case "approve":
		return approval.NewStaticApprover(true, "test-auto-approve")
	case "deny":
		return approval.NewStaticApprover(false, "test-auto-deny")
	}
	const timeout = 2 * time.Minute
	if os.Getenv(approval.EnvApprover) == "local" {
		dir, err := approval.DefaultLocalDir()
		if err == nil {
			var a *approval.LocalApprover
			if a, err = approval.NewLocalApprover(dir, timeout); err == nil {
				logger.Printf("Phase 5 approval gate ON — local socket in %s (decide with `nockguard approvals`), %s timeout, fail-safe deny", dir, timeout)
				return a
			}
		}
		logger.Printf("Phase 5 approval gate: local approver REFUSED to start (%v); ALL gated calls fail CLOSED", err)
		return nil
	}
	// Real approver: a DEDICATED Telegram bot (never the fleet's main bot). The
	// bot token, chat ID and approver IDs must be set; otherwise gated calls fail
	// closed. These values are read HERE, in the proxy
	// process; the proxy strips the same names from the upstream child so the
	// policed agent can never read the token and self-approve (see approval.CredEnvNames).
	token := os.Getenv(approval.EnvBotToken)
	chatID := os.Getenv(approval.EnvChatID)
	if token != "" && chatID != "" {
		a, err := approval.NewTelegramApprover(token, chatID, os.Getenv(approval.EnvApproverIDs), timeout)
		if err != nil {
			logger.Printf("Phase 5 approval gate: Telegram approver REFUSED to start (%v); ALL gated calls fail CLOSED", err)
			return nil
		}
		logger.Printf("Phase 5 approval gate ON — Telegram (dedicated bot), %s timeout, fail-safe deny", timeout)
		return a
	}
	logger.Printf("Phase 5 approval gate: no approver configured (set NOCKGUARD_APPROVAL_BOT_TOKEN + NOCKGUARD_APPROVAL_CHAT_ID + NOCKGUARD_APPROVER_IDS); ALL gated calls fail CLOSED — both `ask` rules and legacy `require_approval` rules will be DENIED until an approver is wired")
	return nil
}

// closeApprover removes the local approver's own socket on exit; other
// approvers hold nothing on disk.
func closeApprover(a approval.Approver) {
	if c, ok := a.(io.Closer); ok {
		_ = c.Close()
	}
}

func main() {
	os.Exit(runCLI(os.Args[1:]))
}

func runCLI(args []string) int {
	if len(args) == 0 {
		printUsage()
		return 0
	}
	// The Wall is a companion binary shipped beside nockguard. Dispatch it
	// before handling --help so Wall flags, including --help, pass through.
	if args[0] == "wall" {
		return runWall(args[1:])
	}
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			printUsage()
			return 0
		}
	}

	if args[0] == "version" {
		fmt.Println("nockguard v0.11.0")
		return 0
	}

	if args[0] == "approvals" {
		return runApprovals(args[1:])
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

	// `selftest` is proof-of-BLOCK — it proves policy actually DENIES a denied
	// tool and input-validation catches a secret. Deliberately NOT `verify`,
	// which proves audit-TRAIL integrity; the two answer different questions.
	if args[0] == "selftest" {
		return runSelftest(args[1:])
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
	if args[0] == "status" || args[0] == "doctor" {
		return runStatus(args[1:])
	}

	if args[0] == "egress-proxy" {
		return runEgressProxy(args[1:])
	}

	if args[0] == "mcp-listen" {
		return runMCPListen(args[1:])
	}
	if args[0] == "mcp-gateway" {
		return runMCPGateway(args[1:])
	}

	if args[0] == "mcp-http" {
		return runMCPHTTP(args[1:])
	}

	if args[0] != "proxy" {
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", args[0])
		printUsage()
		return 1
	}

	var (
		upstreamCmd     string
		upstreamID      string
		agent           string
		policyPath      string
		policyProvided  bool
		auditBestEffort bool
	)

	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.StringVar(&upstreamCmd, "upstream", "", "upstream command")
	fs.StringVar(&upstreamID, "upstream-id", "", "stable upstream ID for tool pins")
	fs.StringVar(&agent, "agent", "", "agent name")
	fs.StringVar(&policyPath, "policy", "", "policy file")
	fs.BoolVar(&auditBestEffort, "audit-best-effort", false, "allow forwarding after audit failures")
	if err := fs.Parse(args[1:]); err != nil {
		return 1
	}
	if strings.HasPrefix(upstreamID, "--") {
		fmt.Fprintln(os.Stderr, "error: --upstream-id requires a value")
		return 1
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "error: unexpected argument %q\n", fs.Arg(0))
		return 1
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "policy" {
			policyProvided = true
		}
	})
	if policyProvided && policyPath == "" {
		fmt.Fprintln(os.Stderr, "error: --policy requires a non-empty path")
		return 1
	}

	if upstreamCmd == "" {
		fmt.Fprintln(os.Stderr, "error: --upstream is required")
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

	// Zero-config OBSERVE mode. When the user named no --policy AND the default
	// policy file does not exist, start in observe mode (allow all, deny nothing,
	// signed audit trail) instead of erroring — the 30-second try-it path.
	// INVARIANTS, both preserved below: a policy file present at the default path
	// is NEVER bypassed, and an explicit --policy is NEVER bypassed. Only
	// os.IsNotExist triggers observe; any other stat error falls through to
	// policy.Load, which reports it exactly as before.
	var (
		engine  *policy.Engine
		auditor *audit.Auditor
		err     error
	)
	zeroConfig := false
	if !policyProvided {
		if _, statErr := os.Stat(policyPath); os.IsNotExist(statErr) {
			zeroConfig = true
		}
	}

	if zeroConfig {
		if agent == "" {
			agent = defaultObserveAgent
		}
		var auditPath, pubHex string
		engine, auditor, auditPath, pubHex, err = observeSetup(agent)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: zero-config observe setup failed: %v\n", err)
			return 1
		}
		printObserveBanner(os.Stderr, agent, auditPath, pubHex, policyPath)
	} else {
		// A policy file is present or was explicitly named: load-or-error, unchanged.
		if agent == "" {
			fmt.Fprintln(os.Stderr, "error: --agent is required")
			return 1
		}
		engine, err = policy.Load(policyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading policy %s: %v\n", policyPath, err)
			return 1
		}

		// Log any policy load-time warnings (e.g., tools in multiple inject rules)
		for _, warn := range engine.Warnings() {
			fmt.Fprintf(os.Stderr, "warning policy: %s\n", warn)
		}

		// Fail-closed is correct but should never be a silent surprise: if the named
		// agent has neither its own policy nor a "default", every tool will be denied.
		// Warn loudly so the operator fixes the policy instead of debugging a deny-all.
		if !engine.HasPolicyFor(agent) {
			fmt.Fprintf(os.Stderr, "warning: no policy for agent %q and no \"default\" — ALL tools will be DENIED (fail-closed). Add an agent or \"default\" policy in %s.\n", agent, policyPath)
		}

		auditor, err = engine.AuditorFor(agent)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error opening audit trail: %v\n", err)
			return 1
		}
	}
	defer closeAuditorBounded(os.Stderr, auditor.Close, time.Second)

	if err := engine.ValidateToolPinScope(agent, upstreamID); err != nil {
		fmt.Fprintf(os.Stderr, "error: tool pin scope for agent %s: %v\n", agent, err)
		return 1
	}
	if engine.HasToolPinConstraints(agent) && auditBestEffort {
		fmt.Fprintln(os.Stderr, "error: --audit-best-effort is incompatible with tool pins")
		return 1
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

	// auditor was built above: signed observe trail in zero-config mode, or
	// engine.AuditorFor(agent) when a policy file governs this run.

	forwarder, err := engine.Forwarder()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error configuring ops-log forwarder: %v\n", err)
		return 1
	}
	forwarder.Start()
	defer forwarder.Stop()

	logger := log.New(os.Stderr, "[nockguard] ", log.LstdFlags)
	upstream := parseCommand(upstreamCmd)

	approver := buildApprover(logger)
	defer closeApprover(approver)
	p := proxy.NewStdioProxy(upstream, agent, engine, validator, limiter, auditor, forwarder, logger).
		WithUpstreamID(upstreamID).
		WithTrust(trustAccumulator).
		WithApprover(approver)
	if auditBestEffort {
		logger.Print("WARNING: --audit-best-effort enabled: audit write failures will NOT refuse tool calls")
		p.WithBestEffortAudit()
	}
	if err := p.Run(); err != nil {
		logger.Printf("proxy error: %v", err)
		return 1
	}
	return 0
}

func runPolicy(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: nockguard policy (check --policy <file> | propose | shadow-report --agent <name> [--audit-dir <dir> | --audit <path>])")
		return 1
	}
	switch args[0] {
	case "check":
		return runPolicyCheck(args[1:])
	case "propose":
		return runPolicyPropose(args[1:])
	case "shadow-report":
		return runPolicyShadowReport(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown policy command: %s\n", args[0])
		return 1
	}
}

// runPolicyCheck loads a policy with the loader the proxy uses and does
// nothing else: exit 0 means it loaded, 1 means it did not (or bad arguments).
// Load-time warnings print to stderr as the proxy prints them; they keep exit 0.
func runPolicyCheck(args []string) int {
	fs := flag.NewFlagSet("policy check", flag.ContinueOnError)
	path := fs.String("policy", "", "policy file to load")
	if err := fs.Parse(args); err != nil || *path == "" || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: nockguard policy check --policy <file>")
		return 1
	}
	engine, err := policy.Load(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	for _, warn := range engine.Warnings() {
		fmt.Fprintf(os.Stderr, "warning policy: %s\n", warn)
	}
	fmt.Printf("policy loaded: %s\n", *path)
	return 0
}

func runPolicyPropose(args []string) int {
	agent, auditPath, ok := parsePolicyAuditArgs(args)
	if !ok {
		return 1
	}
	proposal, err := policy.ProposeShadowFromAudit(agent, auditPath)
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
			agent: {Mode: "allow", Shadow: proposal.Tools},
		},
	}
	data, err := yaml.Marshal(out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error rendering proposal: %v\n", err)
		return 1
	}
	fmt.Print(string(data))
	for _, tool := range proposal.Skipped {
		fmt.Printf("# Skipped tool name containing glob characters: %q\n", tool)
	}
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
		listen      string
		agent       string
		policyPath  string
		auditPath   string
		enforce     bool
		allowRemote bool
	)

	fs := flag.NewFlagSet("egress-proxy", flag.ContinueOnError)
	fs.StringVar(&listen, "listen", "", "listen address")
	fs.StringVar(&agent, "agent", "", "agent name")
	fs.StringVar(&policyPath, "policy", "", "policy file")
	fs.StringVar(&auditPath, "audit", "", "audit trail path")
	fs.BoolVar(&enforce, "enforce", false, "block denied hosts")
	fs.BoolVar(&allowRemote, "allow-remote", false, "allow a non-loopback listen address")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "error: unexpected argument %q\n", fs.Arg(0))
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
	for _, warn := range engine.Warnings() {
		fmt.Fprintf(os.Stderr, "warning policy: %s\n", warn)
	}
	if err := forwardhttp.ValidateConfig(listen, agent, engine, allowRemote); err != nil {
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
	if err := forwardhttp.New(listen, agent, engine, auditor, logger).WithEnforce(enforce).WithAllowRemote(allowRemote).Run(ctx); err != nil {
		logger.Printf("egress proxy error: %v", err)
		return 1
	}
	return 0
}

func runMCPListen(args []string) int {
	var (
		listen          string
		upstream        string
		agent           string
		policyPath      string
		auditPath       string
		auditBestEffort bool
	)

	fs := flag.NewFlagSet("mcp-listen", flag.ContinueOnError)
	fs.StringVar(&listen, "listen", "", "loopback listen address")
	fs.StringVar(&upstream, "upstream", "", "upstream HTTP MCP URL")
	fs.StringVar(&agent, "agent", "", "agent name")
	fs.StringVar(&policyPath, "policy", "", "policy file")
	fs.StringVar(&auditPath, "audit", "", "audit trail path")
	fs.BoolVar(&auditBestEffort, "audit-best-effort", false, "allow forwarding after audit failures")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "error: unexpected argument %q\n", fs.Arg(0))
		return 1
	}

	if listen == "" {
		fmt.Fprintln(os.Stderr, "error: --listen is required")
		return 1
	}
	if upstream == "" {
		fmt.Fprintln(os.Stderr, "error: --upstream is required (the HTTP MCP upstream URL, e.g. https://command.example.com/mcp)")
		return 1
	}
	parsedUpstream, err := url.Parse(upstream)
	if err != nil || parsedUpstream.Host == "" || (parsedUpstream.Scheme != "http" && parsedUpstream.Scheme != "https") {
		fmt.Fprintf(os.Stderr, "error: --upstream must be an absolute HTTP MCP URL: %q\n", upstream)
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
	for _, warn := range engine.Warnings() {
		fmt.Fprintf(os.Stderr, "warning policy: %s\n", warn)
	}
	if !engine.HasPolicyFor(agent) {
		fmt.Fprintf(os.Stderr, "warning: no policy for agent %q and no \"default\" — ALL tools will be DENIED (fail-closed). Add an agent or \"default\" policy in %s.\n", agent, policyPath)
	}
	if engine.HasToolPinConstraints(agent) {
		fmt.Fprintln(os.Stderr, "error: tool pins currently require the stdio proxy")
		return 1
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
	defer func() {
		if cerr := auditor.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "[nockguard-mcp-listen] error closing audit trail: %v\n", cerr)
		}
	}()

	forwarder, err := engine.Forwarder()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error configuring ops-log forwarder: %v\n", err)
		return 1
	}
	forwarder.Start()
	defer forwarder.Stop()

	logger := log.New(os.Stderr, "[nockguard-mcp-listen] ", log.LstdFlags)
	logger.Printf("starting MCP enforcement listener listen=%s upstream=%s agent=%s policy=%s", listen, parsedUpstream.Redacted(), agent, policyPath)

	approver := buildApprover(logger)
	defer closeApprover(approver)
	gate := proxy.NewStdioProxy(nil, agent, engine, validator, limiter, auditor, forwarder, logger).
		WithTrust(trustAccumulator).
		WithApprover(approver)
	listener := proxy.NewHTTPListener(listen, upstream, gate, logger)
	if auditBestEffort {
		logger.Print("WARNING: --audit-best-effort enabled: audit write failures will NOT refuse tool calls")
		listener.WithBestEffortAudit()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := listener.Run(ctx); err != nil {
		logger.Printf("mcp-listen error: %v", err)
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
// Exit 0 = a non-empty, fully checkpointed trail; 1 = setup error, NO_ROWS or
// UNANCHORED; 2 = trail read or integrity failure after key selection.
// verifyAllAgents verifies EVERY per-agent Ed25519 trail (<agent>.audit.jsonl)
// in the audit dir — the "prove the whole fleet is accountable in one command"
// path behind `nockguard verify --all`. Each trail is checked with that agent's
// own public key (NOCKGUARD_AGENT_<NAME>_ED25519_PUB). Exit 0 = all non-empty
// and fully checkpointed, 2 = any tampered, 1 = any empty, unanchored or
// unverifiable trail, or no trails found (NO_TRAILS is not protected).
type verifyResult struct {
	Verdict         string                `json:"verdict"`
	AuditPath       string                `json:"audit_path,omitempty"`
	PubKeySource    string                `json:"public_key_source,omitempty"`
	EntriesVerified int                   `json:"entries_verified"`
	Error           string                `json:"error,omitempty"`
	Completeness    []audit.RunAssessment `json:"completeness,omitempty"`
}

// closeAuditorBounded closes the audit writer without letting a stuck write
// hold process exit forever. The proxy has already written or skipped its run
// close row by now, so a timeout says only that a write is still in flight;
// the trail itself records whether the run closed.
func closeAuditorBounded(w io.Writer, closeFn func() error, timeout time.Duration) {
	closed := make(chan error, 1)
	go func() { closed <- closeFn() }()
	select {
	case err := <-closed:
		if err != nil {
			fmt.Fprintf(w, "audit close failed: %v\n", err)
		}
	case <-time.After(timeout):
		fmt.Fprintln(w, "audit close timed out: an audit write is still in progress; check the run with nockguard verify --completeness")
	}
}

// readVerifySnapshot reads the checkpoint and trail as one consistent
// snapshot. A regular trail is held under the shared flock that signed writers
// take exclusively for each append and checkpoint update, so a live writer
// cannot land a row or checkpoint between the two reads. The checkpoint is read
// first so that, even without the lock, its count never runs ahead of the trail.
func readVerifySnapshot(path string) (trail, hwm []byte, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if info.Mode().IsRegular() {
		if err := audit.LockShared(f.Fd()); err != nil {
			return nil, nil, fmt.Errorf("locking audit trail: %w", err)
		}
		defer func() { _ = audit.UnlockFile(f.Fd()) }()
	}
	hwm, err = os.ReadFile(path + ".hwm")
	if os.IsNotExist(err) {
		hwm, err = nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	trail, err = io.ReadAll(f)
	if err != nil {
		return nil, nil, err
	}
	return trail, hwm, nil
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
	PubKeySource    string `json:"public_key_source,omitempty"`
	EntriesVerified int    `json:"entries_verified"`
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
		// Nothing to verify is the absence of evidence, never PROTECTED.
		// Same exit class as UNVERIFIABLE: we could not verify anything.
		if jsonOutput {
			writeJSON(verifyAllResult{Verdict: "NO_TRAILS", AuditDir: baseDir, Trails: []verifyTrailResult{}})
		} else {
			fmt.Printf("No per-agent audit trails (*%s) found in %s\n", suffix, baseDir)
			fmt.Println("Nothing to verify: an empty audit dir is not evidence of protection.")
			fmt.Println("VERDICT: NO_TRAILS")
		}
		return 1
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
		pubHex, keySource, kerr := requirePubHex(envName, agent)
		if kerr != nil {
			msg := kerr.Error()
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
		n, checkpointCount, verr := audit.VerifyEd25519WithCheckpoint(path, pub)
		if verr != nil {
			if !jsonOutput {
				fmt.Printf("  [TAMPER] %-18s %v\n", agent, verr)
			}
			results = append(results, verifyTrailResult{Agent: agent, Path: path, Status: "TAMPERED", PubKeySource: keySource, EntriesVerified: n, Error: verr.Error()})
			tampered++
			continue
		}
		trailVerdict := sessionverify.GuardVerdict(n, checkpointCount == n)
		if trailVerdict != sessionverify.VerdictProtected {
			detail := "audit trail is empty; there are no entries to verify"
			label := "[NO ROWS]"
			if trailVerdict == sessionverify.VerdictUnanchored {
				detail = fmt.Sprintf("%d entries beyond the signed checkpoint (count %d); re-run once the writer is idle", n-checkpointCount, checkpointCount)
				label = "[UNANCHORED]"
			}
			if !jsonOutput {
				fmt.Printf("  %-12s %-18s %s\n", label, agent, detail)
			}
			results = append(results, verifyTrailResult{Agent: agent, Path: path, Status: trailVerdict, PubKeySource: keySource, EntriesVerified: n, Error: detail})
			unverifiable++
			continue
		}
		if !jsonOutput {
			fmt.Printf("  [OK]     %-18s %d entries, chain intact (public key: %s)\n", agent, n, keySource)
		}
		results = append(results, verifyTrailResult{Agent: agent, Path: path, Status: "PROTECTED", PubKeySource: keySource, EntriesVerified: n})
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
	// `verify --session <id>` is the unified NockGuard + NockLock session
	// verdict (verify_session.go). It has its own flag set and never falls
	// through to the single-trail modes below.
	if hasSessionFlag(args[1:]) {
		return runVerifySession(args[1:])
	}
	for _, arg := range args[1:] {
		if arg == "--export" || arg == "-export" || strings.HasPrefix(arg, "--export=") || strings.HasPrefix(arg, "-export=") {
			return runVerifyExport(args[1:])
		}
	}
	var auditPath, auditDir, agentName, keyEnv, pubEnv string
	allMode := false
	jsonOutput := false
	completeness := false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--all":
			allMode = true
		case "--json":
			jsonOutput = true
		case "--completeness":
			completeness = true
		case "--audit":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --audit requires a value")
				return 1
			}
			i++
			auditPath = args[i]
			if auditPath == "" {
				fmt.Fprintln(os.Stderr, "error: --audit requires a non-empty path")
				return 1
			}
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
		if completeness {
			fmt.Fprintln(os.Stderr, "error: --completeness requires a single trail")
			return 1
		}
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

	// Per-agent mode: derive the public key from the agent and the trail path only when absent.
	if agentName != "" {
		if !policy.ValidAgentName(agentName) {
			fmt.Fprintf(os.Stderr, "error: invalid agent name %q: only alphanumerics, hyphens, and dots are allowed\n", agentName)
			return 1
		}
		if auditPath == "" {
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
		}
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
		n               int
		checkpointCount int
		err             error
		keySource       string
		trailSnapshot   []byte
		hwmSnapshot     []byte
	)
	if completeness {
		trailSnapshot, hwmSnapshot, err = readVerifySnapshot(auditPath)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading audit snapshot: %v\n", err)
		return 1
	}
	if pubEnv != "" {
		pubHex, src, kerr := requirePubHex(pubEnv, agentName)
		keySource = src
		if kerr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", kerr)
			return 1
		}
		pub, perr := audit.PublicKeyFromHex(pubHex)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", perr)
			return 1
		}
		if completeness {
			n, checkpointCount, err = audit.VerifyEd25519WithCheckpointBytes(trailSnapshot, hwmSnapshot, pub)
		} else {
			n, checkpointCount, err = audit.VerifyEd25519WithCheckpoint(auditPath, pub)
		}
	} else {
		key := os.Getenv(keyEnv)
		if key == "" {
			fmt.Fprintf(os.Stderr, "error: %s is not set in the environment\n", keyEnv)
			return 1
		}
		if completeness {
			n, checkpointCount, err = audit.VerifyWithCheckpointBytes(trailSnapshot, hwmSnapshot, []byte(key))
		} else {
			n, checkpointCount, err = audit.VerifyWithCheckpoint(auditPath, []byte(key))
		}
	}

	if err != nil {
		if jsonOutput {
			writeJSON(verifyResult{Verdict: "TAMPERED", AuditPath: auditPath, EntriesVerified: n, Error: err.Error()})
		} else {
			fmt.Fprintf(os.Stderr, "TAMPER DETECTED — %s (verified %d before the break): %v\n", auditPath, n, err)
		}
		return 2
	}
	verdict := sessionverify.GuardVerdict(n, checkpointCount == n)
	if verdict != sessionverify.VerdictProtected {
		detail := "audit trail is empty; there are no entries to verify"
		if verdict == sessionverify.VerdictUnanchored {
			detail = fmt.Sprintf("%d entries beyond the signed checkpoint (count %d); re-run once the writer is idle", n-checkpointCount, checkpointCount)
		}
		if jsonOutput {
			writeJSON(verifyResult{Verdict: verdict, AuditPath: auditPath, PubKeySource: keySource, EntriesVerified: n, Error: detail})
		} else {
			fmt.Printf("NOT PROTECTED — %s: %s\n", verdict, detail)
			if keySource != "" {
				fmt.Printf("public key: %s\n", keySource)
			}
			fmt.Printf("VERDICT: %s\n", verdict)
		}
		return 1
	}
	var assessment []audit.RunAssessment
	if completeness {
		assessment = audit.AssessRuns(trailSnapshot, true, time.Now())
	}
	if jsonOutput {
		writeJSON(verifyResult{Verdict: "PROTECTED", AuditPath: auditPath, PubKeySource: keySource, EntriesVerified: n, Completeness: assessment})
	} else {
		fmt.Printf("OK — %d entries verified, hash chain intact: %s\n", n, auditPath)
		if keySource != "" {
			fmt.Printf("public key: %s\n", keySource)
		}
		fmt.Println("VERDICT: PROTECTED")
		for _, run := range assessment {
			fmt.Printf("COMPLETENESS: %s run_id=%s — %s\n", run.Verdict, run.RunID, run.Reason)
		}
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
		pubHex, _, kerr := requirePubHex(pubEnv, agentName)
		if kerr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", kerr)
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

func runStatus(args []string) int {
	var agent, path string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--agent", "--audit":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "error: %s requires a value\n", args[i])
				return 1
			}
			flag := args[i]
			i++
			if flag == "--agent" {
				agent = args[i]
			} else {
				path = args[i]
			}
		default:
			fmt.Fprintf(os.Stderr, "error: unknown status flag %q\n", args[i])
			return 1
		}
	}
	if !policy.ValidAgentName(agent) {
		fmt.Fprintln(os.Stderr, "usage: nockguard status --agent <name> [--audit <path>]")
		return 1
	}
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot determine home directory: %v\n", err)
			return 1
		}
		path = policy.AgentAuditPath(filepath.Join(home, policy.DefaultAuditPath), agent)
	}
	if audit.FailureStatus(path) {
		fmt.Printf("agent: %s\naudit: last required audit write failed\n", agent)
		return 2
	}
	fmt.Printf("agent: %s\naudit: no failure reported\n", agent)
	return 0
}

// runInit handles `nockguard init` — it scaffolds a sensible, default-deny
// starter policy so a new user is guarded in seconds instead of hand-writing
// YAML. It never overwrites an existing policy without --force.
func runInit(args []string) int {
	var policyPath string
	force := false
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.StringVar(&policyPath, "policy", "", "policy file to create")
	fs.BoolVar(&force, "force", false, "overwrite an existing policy")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "error: unexpected argument %q\n", fs.Arg(0))
		return 1
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
	fmt.Println("  1. Run nockguard keygen --agent coder to create a signing key.")
	fmt.Println("  2. Run the firewall in front of the filesystem MCP server:")
	fmt.Printf("     nockguard proxy --upstream \"npx -y @modelcontextprotocol/server-filesystem <dir>\" --agent coder --policy %s\n", policyPath)
	return 0
}

// runMCPHTTP implements the `mcp-http` subcommand: an MCP stdio↔HTTP bridge
// that audits each tools/call before forwarding when audit is enabled. See
// docs/http-mcp-interception.md for design rationale and the full cutover plan.
func runMCPHTTP(args []string) int {
	var (
		upstreamURL     string
		agent           string
		policyPath      string
		authEnv         string
		auditBestEffort bool
	)
	fs := flag.NewFlagSet("mcp-http", flag.ContinueOnError)
	fs.StringVar(&upstreamURL, "upstream", "", "upstream HTTP MCP URL")
	fs.StringVar(&agent, "agent", "", "agent name")
	fs.StringVar(&policyPath, "policy", "", "policy file")
	fs.StringVar(&authEnv, "auth-env", "", "environment variable with upstream authorization")
	fs.BoolVar(&auditBestEffort, "audit-best-effort", false, "allow forwarding after audit failures")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "error: unexpected argument %q\n", fs.Arg(0))
		return 1
	}

	if upstreamURL == "" {
		fmt.Fprintln(os.Stderr, "error: --upstream is required (the HTTP MCP upstream URL, e.g. https://command.example.com/mcp)")
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
	if engine.HasToolPinConstraints(agent) {
		fmt.Fprintln(os.Stderr, "error: tool pins require the stdio proxy with a session-scoped tool catalog")
		return 1
	}

	for _, warn := range engine.Warnings() {
		fmt.Fprintf(os.Stderr, "warning policy: %s\n", warn)
	}

	auditor, err := engine.AuditorFor(agent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening audit trail: %v\n", err)
		return 1
	}
	defer auditor.Close()

	authHeader := ""
	if authEnv != "" {
		authHeader = os.Getenv(authEnv)
		if authHeader == "" {
			fmt.Fprintf(os.Stderr, "warning: --auth-env %s is set but the variable is empty — upstream requests will have no Authorization header\n", authEnv)
		}
	}

	logger := log.New(os.Stderr, "[nockguard-mcp-http] ", log.LstdFlags)
	logger.Printf("starting MCP HTTP proxy upstream=%s agent=%s policy=%s observe-only=true", upstreamURL, agent, policyPath)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	bridge := mcphttp.New(upstreamURL, agent, authHeader, auditor, logger)
	if auditBestEffort {
		logger.Print("WARNING: --audit-best-effort enabled: audit write failures will NOT refuse tool calls")
		bridge.WithBestEffortAudit()
	}
	if err := bridge.Run(ctx); err != nil {
		logger.Printf("mcp-http proxy error: %v", err)
		return 1
	}
	return 0
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `nockguard — MCP firewall for AI agent fleets

Usage:
  nockguard init [--policy <path>] [--force]
  nockguard proxy --upstream <command> --agent <name> [--policy <path>] [--audit-best-effort]
  nockguard mcp-http --upstream <url> --agent <name> [--policy <path>] [--auth-env <ENV>] [--audit-best-effort]
  nockguard mcp-listen --listen 127.0.0.1:<port> --upstream <url> --agent <name> [--policy <path>] [--audit <path>] [--audit-best-effort]
  nockguard mcp-gateway --config <path>  (OAuth resource behind a loopback HTTPS ingress)
  nockguard egress-proxy --listen <addr> --agent <name> [--policy <path>] [--audit <path>] [--enforce] [--allow-remote]
  nockguard verify (--all | --agent <name> | --key-env <ENV> | --ed25519-pub-env <ENV>) [--audit <path>] [--audit-dir <dir>]
  nockguard verify --session <id> --lock-db <path> --guard-trail <path> (--pub-env <ENV> | --lock-pub-env <ENV> --guard-pub-env <ENV>) [--json]
  nockguard verify --export <wall.proof.json> (--agent <name> | --ed25519-pub-env <ENV>)
  nockguard selftest [--policy <path>] [--json]
  nockguard status --agent <name> [--audit <path>]  (alias: doctor)
  nockguard policy propose --agent <name> [--audit <path>] [--audit-dir <dir>]
  nockguard policy shadow-report --agent <name> [--audit <path>] [--audit-dir <dir>]
  nockguard trust show --agent <name>
  nockguard audit verify ...   # same as 'nockguard verify' (the audit-namespaced form)
  nockguard evidence --framework soc2 (--agent <name> | --ed25519-pub-env <ENV> | --key-env <ENV>) [--audit <path>] [--audit-dir <dir>] [--from <date>] [--to <date>] [--format html|json] [-o <file>]
  nockguard wall [Wall flags...]  (starts the nockguard-wall companion)
  nockguard approvals (list | approve <id> | deny <id> | prune)  (decide calls held by NOCKGUARD_APPROVER=local; prune removes dead sockets)
  nockguard keygen [--agent <name>] [--force] [--print-env]
  nockguard version

Options:
  --upstream         MCP server command to proxy (for: proxy) or HTTP MCP upstream URL (for: mcp-http, mcp-listen)
  --upstream-id      Stable operator-chosen upstream ID for stdio tool pins (for: proxy)
  --auth-env         Env var whose value is sent as the Authorization header to the HTTP upstream (for: mcp-http)
  --allow-remote     Permit a non-loopback egress-proxy bind (warns; no caller authentication)
  --listen           Listen address (for: mcp-listen use explicit loopback only; for: egress-proxy loopback unless --allow-remote)
  --agent            Agent identity for policy lookup / per-agent keypair flow
  --policy           Path to policy YAML (default: ~/.nockguard/policy.yaml)
  --enforce          Block denied egress hosts (returns 403); default is observe-only (logs but allows)
  --force            Overwrite an existing policy (for: init) or existing key files (for: keygen)
  --print-env        Print the keygen env lines, INCLUDING the secret seed, to stdout instead of writing key files (for: keygen)
  --key-env          Env var holding the HMAC signing key (tamper-evident verify)
  --ed25519-pub-env  Env var holding the hex Ed25519 public key (public-key verification)
  --audit            Path to the audit JSONL (default: ~/.nockguard/logs/audit.jsonl)
  --audit-best-effort  Permit local tool calls when enabled audit writes fail; off by default (proxy, mcp-http, mcp-listen)
  --audit-dir        Directory holding per-agent audit files (for: audit verify / evidence --agent)
  --session          nocklock session id to verify across the NockLock log and a NockGuard trail (for: verify)
  --lock-db          Path to the NockLock SQLite audit log (for: verify --session; required, no discovery)
  --guard-trail      Path to the NockGuard Ed25519 JSONL trail (for: verify --session; required, no discovery)
  --pub-env          Env var holding one hex Ed25519 public key used for BOTH chains (for: verify --session)
  --lock-pub-env / --guard-pub-env   Env vars holding each chain's hex Ed25519 public key (for: verify --session)
  --framework        Compliance framework to map against (for: evidence) — soc2 (gdpr/pci/hipaa are stubs)
  --from / --to      Inclusive date filter for evidence entries (YYYY-MM-DD or RFC3339)
  --format           Evidence output format: html (default) or json
  -o, --output       Write the evidence pack to a file instead of stdout

Per-agent signing:
  Each agent gets its own Ed25519 keypair. The trail is signed with the agent's
  private key and written to <agent>.audit.jsonl, verifiable with only that
  agent's public key. Verification checks the recorded bytes against that key.
  A private-key holder can sign new records; identifying the software that
  performed an action requires additional evidence.
  keygen writes ~/.nockguard/keys/<agent>.ed25519 (seed, 0600) and <agent>.pub;
  proxy and verify --agent find them by name when the NOCKGUARD_AGENT_<NAME>_*
  env vars are unset (the env vars win when set).

Evidence packs:
  `+"`nockguard evidence`"+` reads the SAME signed trail `+"`audit verify`"+` checks, maps its
  entries onto a framework's controls (SOC 2 today), and renders an Integrity
  Attestation. A broken chain renders a prominent FAILED banner and exits 2 — the
  pack is still produced so the break is visible, never silently dropped.

Examples:
  nockguard init                                        # scaffold a default-deny starter policy
  nockguard proxy --upstream "npx -y @modelcontextprotocol/server-filesystem /path/to/project"   # zero-config observe: no --policy flag and no ~/.nockguard/policy.yaml
  nockguard proxy --upstream "npx -y @modelcontextprotocol/server-filesystem /path/to/project" --agent coder --policy policy.yaml
  nockguard mcp-http --upstream https://mcp.example.com/mcp --agent coder --auth-env MCP_AUTH
  nockguard mcp-listen --listen 127.0.0.1:8790 --upstream https://mcp.example.com/mcp --agent coder --policy policy.yaml
  nockguard egress-proxy --listen 127.0.0.1:8899 --agent coder --policy egress.yaml
  nockguard keygen --agent coder                        # write per-agent keypair to ~/.nockguard/keys (seed never printed)
  nockguard verify --agent coder                        # exit 0 = non-empty, fully checkpointed; 1 = setup/key error, NO_ROWS or UNANCHORED; 2 = tampered
  nockguard selftest --policy policy.yaml               # prove the firewall BLOCKS a denied tool + catches a secret (exit 0 = proven, 2 = gap)
  nockguard verify --session "$NOCKLOCK_SESSION_ID" --lock-db <nocklock.db> --guard-trail ~/.nockguard/logs/coder.audit.jsonl --lock-pub-env LOCK_PUB --guard-pub-env GUARD_PUB   # one verdict across both chains (exit 0 = PROTECTED, 2 = TAMPERED, 1 = anything else)
  nockguard verify --all                                # prove EVERY per-agent trail in ~/.nockguard/logs (exit 0 = all protected, 2 = tampered, 1 = NO_ROWS, UNANCHORED, unverifiable or no trails)
  nockguard policy propose --agent coder                 # derive a shadow allowlist from coder's observed allowed tools
  nockguard policy shadow-report --agent coder           # count shadow would-deny misses by tool
  nockguard evidence --framework soc2 --agent coder -o coder-soc2.html   # SOC2 pack for coder's signed trail
  nockguard keygen                                      # keypair for the "default" identity
  nockguard audit verify --ed25519-pub-env NOCKGUARD_AUDIT_ED25519_PUB  # verify global trail`)
}
