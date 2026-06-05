package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/policy"
	"github.com/nocktechnologies/nockguard/internal/proxy"
)

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
		home, _ := os.UserHomeDir()
		policyPath = home + "/.nockguard/policy.yaml"
	}

	engine, err := policy.Load(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading policy %s: %v\n", policyPath, err)
		os.Exit(1)
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

	auditor, err := engine.Auditor()
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

	p := proxy.NewStdioProxy(upstream, agent, engine, validator, limiter, auditor, forwarder, logger)
	if err := p.Run(); err != nil {
		logger.Fatalf("proxy error: %v", err)
	}
}

func parseCommand(cmd string) []string {
	return strings.Fields(cmd)
}

// runAudit handles `nockguard audit verify` — it walks the signed audit trail and
// checks the HMAC hash chain end to end, proving no entry was edited, deleted,
// reordered, or inserted. Exit 0 = intact, 2 = tampering detected, 1 = usage/setup.
func runAudit(args []string) {
	if len(args) == 0 || args[0] != "verify" {
		fmt.Fprintln(os.Stderr, "usage: nockguard audit verify --key-env <ENV> [--audit <path>]")
		os.Exit(1)
	}
	var auditPath, keyEnv string
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--audit":
			if i+1 < len(args) {
				i++
				auditPath = args[i]
			}
		case "--key-env":
			if i+1 < len(args) {
				i++
				keyEnv = args[i]
			}
		}
	}
	if auditPath == "" {
		home, _ := os.UserHomeDir()
		auditPath = filepath.Join(home, policy.DefaultAuditPath)
	}
	if keyEnv == "" {
		fmt.Fprintln(os.Stderr, "error: --key-env <ENV> is required (the env var holding the signing key)")
		os.Exit(1)
	}
	key := os.Getenv(keyEnv)
	if key == "" {
		fmt.Fprintf(os.Stderr, "error: %s is not set in the environment\n", keyEnv)
		os.Exit(1)
	}
	n, err := audit.Verify(auditPath, []byte(key))
	if err != nil {
		fmt.Fprintf(os.Stderr, "TAMPER DETECTED — %s (verified %d before the break): %v\n", auditPath, n, err)
		os.Exit(2)
	}
	fmt.Printf("OK — %d entries verified, hash chain intact: %s\n", n, auditPath)
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `nockguard — MCP firewall for AI agent fleets

Usage:
  nockguard proxy --upstream <command> --agent <name> [--policy <path>]
  nockguard audit verify --key-env <ENV> [--audit <path>]
  nockguard version

Options:
  --upstream  MCP server command to proxy (required)
  --agent     Agent identity for policy lookup (required)
  --policy    Path to policy YAML (default: ~/.nockguard/policy.yaml)
  --key-env   Env var holding the audit signing key (for: audit verify)
  --audit     Path to the audit JSONL (default: ~/.nockguard/logs/audit.jsonl)

Examples:
  nockguard proxy --upstream "npx mcp-server-nockcc" --agent kit --policy policy.yaml
  nockguard audit verify --key-env NOCKGUARD_AUDIT_KEY`)
}
