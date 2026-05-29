package main

import (
	"fmt"
	"log"
	"os"
	"strings"

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

	logger := log.New(os.Stderr, "[nockguard] ", log.LstdFlags)
	upstream := parseCommand(upstreamCmd)

	p := proxy.NewStdioProxy(upstream, agent, engine, validator, logger)
	if err := p.Run(); err != nil {
		logger.Fatalf("proxy error: %v", err)
	}
}

func parseCommand(cmd string) []string {
	return strings.Fields(cmd)
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `nockguard — MCP firewall for AI agent fleets

Usage:
  nockguard proxy --upstream <command> --agent <name> [--policy <path>]
  nockguard version

Options:
  --upstream  MCP server command to proxy (required)
  --agent     Agent identity for policy lookup (required)
  --policy    Path to policy YAML (default: ~/.nockguard/policy.yaml)

Example:
  nockguard proxy --upstream "npx mcp-server-nockcc" --agent kit --policy policy.yaml`)
}
