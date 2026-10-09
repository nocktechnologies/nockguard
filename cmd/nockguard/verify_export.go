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
	pubHex, kerr := requirePubHex(*pubEnv, *agent)
	if kerr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", kerr)
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
	data, err := io.ReadAll(io.LimitReader(f, audit.MaxExportProofBytes+1))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if len(data) > audit.MaxExportProofBytes {
		fmt.Fprintln(os.Stderr, "export proof exceeds 256 MiB")
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
	fmt.Printf("Scope: agent=%q captured_at=%q since=%q until=%q severity=%q decision=%q q=%q\n", proof.Agent, proof.CapturedAt, proof.Filters.Since, proof.Filters.Until, proof.Filters.Severity, proof.Filters.Decision, proof.Filters.Query)
	if complete {
		if proof.Filters.Since == "" && proof.Filters.Until == "" {
			fmt.Println("VERDICT: PROTECTED — complete trail")
		} else if proof.Filters.Until == "" {
			fmt.Println("VERDICT: PROTECTED — complete through signed checkpoint; no explicit upper time bound")
		} else {
			fmt.Printf("VERDICT: PROTECTED — complete time window through %s\n", proof.Filters.Until)
		}
	} else {
		fmt.Println("VERDICT: PROTECTED — integrity verified; not a complete window")
	}
	return 0
}
