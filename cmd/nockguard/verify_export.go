package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/policy"
)

func runVerifyExport(args []string) int {
	fs := flag.NewFlagSet("verify --export", flag.ContinueOnError)
	path := fs.String("export", "", "Wall proof file")
	agent := fs.String("agent", "", "agent whose public key verifies the proof")
	pubEnv := fs.String("ed25519-pub-env", "", "environment variable holding the Ed25519 public key")
	if err := fs.Parse(args); err != nil || *path == "" || fs.NArg() != 0 || (*agent == "") == (*pubEnv == "") {
		fmt.Fprintln(os.Stderr, "usage: nockguard verify --export <file> (--agent <name> | --ed25519-pub-env <ENV>)")
		return 1
	}
	if *agent != "" {
		if !policy.ValidAgentName(*agent) {
			fmt.Fprintln(os.Stderr, "invalid agent name")
			return 1
		}
		*pubEnv = policy.AgentPubKeyEnvName(*agent)
	}
	pubHex := os.Getenv(*pubEnv)
	if pubHex == "" {
		fmt.Fprintf(os.Stderr, "error: %s is not set\n", *pubEnv)
		return 1
	}
	pub, err := audit.PublicKeyFromHex(pubHex)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	f, err := os.Open(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 128<<20+1))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if len(data) > 128<<20 {
		fmt.Fprintln(os.Stderr, "export proof exceeds 128 MiB")
		return 1
	}
	n, complete, err := audit.VerifyExport(data, pub, *agent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "TAMPER DETECTED — export proof failed: %v\n", err)
		return 2
	}
	fmt.Printf("OK — %d exported rows verified against the signed chain head\n", n)
	var proof audit.ExportProof
	_ = json.Unmarshal(data, &proof) // already parsed and checked by VerifyExport
	fmt.Printf("Scope: agent=%q since=%q until=%q severity=%q decision=%q q=%q\n", proof.Agent, proof.Filters.Since, proof.Filters.Until, proof.Filters.Severity, proof.Filters.Decision, proof.Filters.Query)
	if complete {
		fmt.Println("VERDICT: PROTECTED — complete time window")
	} else {
		fmt.Println("VERDICT: PROTECTED — integrity verified; not a complete window")
	}
	return 0
}
