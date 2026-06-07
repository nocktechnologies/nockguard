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
	"github.com/nocktechnologies/nockguard/internal/policy"
	"github.com/nocktechnologies/nockguard/internal/proxy"
)

// buildApprover wires the Phase 5 approval gate. For now: a deterministic test
// seam (NOCKGUARD_APPROVAL_TEST=approve|deny) used by e2e tests, otherwise no
// approver (nil) — the real Telegram approver lands in the next piece. nil means
// require_approval rules are present but un-enforced; that is logged loud so a
// deployment never silently skips the gate.
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
	logger.Printf("Phase 5 approval gate: no approver configured (set NOCKGUARD_APPROVAL_BOT_TOKEN + NOCKGUARD_APPROVAL_CHAT_ID); require_approval rules are present but un-enforced")
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
		runKeygen()
		return
	}

	if args[0] == "init" {
		runInit(args[1:])
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

	p := proxy.NewStdioProxy(upstream, agent, engine, validator, limiter, auditor, forwarder, logger).
		WithApprover(buildApprover(logger))
	if err := p.Run(); err != nil {
		logger.Fatalf("proxy error: %v", err)
	}
}

func parseCommand(cmd string) []string {
	return strings.Fields(cmd)
}

// runAudit handles `nockguard audit verify` — it walks the signed audit trail and
// checks the hash chain end to end, proving no entry was edited, deleted,
// reordered, or inserted. With --key-env it checks the symmetric HMAC chain
// (tamper-evident); with --ed25519-pub-env it checks the Ed25519 chain using only
// the public key (non-repudiable — proves WHO signed). Exit 0 = intact, 2 =
// tampering detected, 1 = usage/setup.
func runAudit(args []string) {
	if len(args) == 0 || args[0] != "verify" {
		fmt.Fprintln(os.Stderr, "usage: nockguard audit verify (--key-env <ENV> | --ed25519-pub-env <ENV>) [--audit <path>]")
		os.Exit(1)
	}
	var auditPath, keyEnv, pubEnv string
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
		case "--ed25519-pub-env":
			if i+1 < len(args) {
				i++
				pubEnv = args[i]
			}
		}
	}
	if auditPath == "" {
		home, _ := os.UserHomeDir()
		auditPath = filepath.Join(home, policy.DefaultAuditPath)
	}
	if (keyEnv == "") == (pubEnv == "") {
		fmt.Fprintln(os.Stderr, "error: provide exactly one of --key-env <ENV> (HMAC) or --ed25519-pub-env <ENV> (Ed25519 public key)")
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

// runKeygen generates a fresh Ed25519 keypair for non-repudiable audit signing.
// The private SEED is the secret the proxy signs with — set it in the signing env
// (audit.sign_ed25519_key_env), keep it out of version control. The PUBLIC key is
// what verifiers use; it cannot produce signatures, so it can be shared freely.
func runKeygen() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("# Ed25519 audit signing keypair\n")
	fmt.Printf("# PRIVATE seed — secret. Set as the signing env (sign_ed25519_key_env); never commit.\n")
	fmt.Printf("NOCKGUARD_AUDIT_ED25519_KEY=%s\n\n", hex.EncodeToString(priv.Seed()))
	fmt.Printf("# PUBLIC key — share with verifiers. Cannot forge entries.\n")
	fmt.Printf("NOCKGUARD_AUDIT_ED25519_PUB=%s\n", hex.EncodeToString(pub))
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
		home, _ := os.UserHomeDir()
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
  nockguard audit verify (--key-env <ENV> | --ed25519-pub-env <ENV>) [--audit <path>]
  nockguard keygen
  nockguard version

Options:
  --upstream         MCP server command to proxy (required)
  --agent            Agent identity for policy lookup (required)
  --policy           Path to policy YAML (default: ~/.nockguard/policy.yaml)
  --force            Overwrite an existing policy (for: init)
  --key-env          Env var holding the HMAC signing key (tamper-evident verify)
  --ed25519-pub-env  Env var holding the hex Ed25519 public key (non-repudiable verify)
  --audit            Path to the audit JSONL (default: ~/.nockguard/logs/audit.jsonl)

Examples:
  nockguard init                                        # scaffold a default-deny starter policy
  nockguard proxy --upstream "npx mcp-server-nockcc" --agent kit --policy policy.yaml
  nockguard audit verify --key-env NOCKGUARD_AUDIT_KEY
  nockguard keygen  # generate an Ed25519 keypair for non-repudiable signing
  nockguard audit verify --ed25519-pub-env NOCKGUARD_AUDIT_ED25519_PUB`)
}
