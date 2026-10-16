package main

import (
	"crypto/ed25519"
	"fmt"
	"os"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/sessionverify"
)

// `nockguard verify --session <id>` prints the unified NockGuard + NockLock
// session verdict computed by internal/sessionverify (shared with the Live Wall).
// Exit codes follow `verify`: 0 = PROTECTED, 2 = TAMPERED, 1 = anything else.

const sessionIDTrustNote = "Session IDs come from NOCKLOCK_SESSION_ID in the launching process's environment and are not authenticated."

const sessionUsage = "usage: nockguard verify --session <id> --lock-db <path> --guard-trail <path> (--pub-env <ENV> | --lock-pub-env <ENV> --guard-pub-env <ENV>) [--json]\n" + sessionIDTrustNote

// hasSessionFlag reports whether a verify invocation is the --session form.
func hasSessionFlag(args []string) bool {
	for _, a := range args {
		if a == "--session" {
			return true
		}
	}
	return false
}

func loadPubFromEnv(envName string) (ed25519.PublicKey, error) {
	v := os.Getenv(envName)
	if v == "" {
		return nil, fmt.Errorf("%s is not set in the environment", envName)
	}
	pub, err := audit.PublicKeyFromHex(v)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envName, err)
	}
	return pub, nil
}

// runVerifySession parses the flags after "verify" and runs the check.
func runVerifySession(args []string) int {
	var session, lockDB, guardTrail, pubEnv, lockPubEnv, guardPubEnv string
	var sessionSet, jsonOutput bool
	str := func(i *int, name string, dst *string) bool {
		if *i+1 >= len(args) {
			fmt.Fprintf(os.Stderr, "error: %s requires a value\n%s\n", name, sessionUsage)
			return false
		}
		*i++
		*dst = args[*i]
		return true
	}
	for i := 0; i < len(args); i++ {
		ok := true
		switch args[i] {
		case "--json":
			jsonOutput = true
		case "--session":
			ok = str(&i, "--session", &session)
			sessionSet = true
		case "--lock-db":
			ok = str(&i, "--lock-db", &lockDB)
		case "--guard-trail":
			ok = str(&i, "--guard-trail", &guardTrail)
		case "--pub-env":
			ok = str(&i, "--pub-env", &pubEnv)
		case "--lock-pub-env":
			ok = str(&i, "--lock-pub-env", &lockPubEnv)
		case "--guard-pub-env":
			ok = str(&i, "--guard-pub-env", &guardPubEnv)
		default:
			fmt.Fprintf(os.Stderr, "error: unknown flag %q for verify --session\n%s\n", args[i], sessionUsage)
			return 1
		}
		if !ok {
			return 1
		}
	}
	switch {
	case !sessionSet || session == "":
		fmt.Fprintf(os.Stderr, "error: --session requires a non-empty session id\n%s\n", sessionUsage)
		return 1
	case lockDB == "":
		fmt.Fprintf(os.Stderr, "error: --lock-db <path> is required (no discovery)\n%s\n", sessionUsage)
		return 1
	case guardTrail == "":
		fmt.Fprintf(os.Stderr, "error: --guard-trail <path> is required (no discovery)\n%s\n", sessionUsage)
		return 1
	case pubEnv != "" && (lockPubEnv != "" || guardPubEnv != ""):
		fmt.Fprintf(os.Stderr, "error: use either --pub-env, or both --lock-pub-env and --guard-pub-env, not both forms\n%s\n", sessionUsage)
		return 1
	case pubEnv == "" && (lockPubEnv == "" || guardPubEnv == ""):
		fmt.Fprintf(os.Stderr, "error: a public key is required for each chain: --pub-env <ENV>, or both --lock-pub-env and --guard-pub-env\n%s\n", sessionUsage)
		return 1
	}
	if pubEnv != "" {
		lockPubEnv, guardPubEnv = pubEnv, pubEnv
	}
	lockPub, err := loadPubFromEnv(lockPubEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: lock key: %v\n", err)
		return 1
	}
	guardPub, err := loadPubFromEnv(guardPubEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: guard key: %v\n", err)
		return 1
	}

	res := sessionverify.Verify(session, lockDB, lockPub, guardTrail, guardPub)
	if jsonOutput {
		writeJSON(struct {
			sessionverify.Result
			SessionIDNote string `json:"session_id_note"`
		}{res, sessionIDTrustNote})
	} else {
		printSessionResult(res)
	}
	return sessionExitCode(res.Verdict)
}

func sessionExitCode(verdict string) int {
	switch verdict {
	case sessionverify.VerdictProtected:
		return 0
	case sessionverify.VerdictTampered:
		return 2
	default:
		return 1
	}
}

func printSessionResult(res sessionverify.Result) {
	fmt.Printf("Session %s\n", res.SessionID)
	fmt.Println(sessionIDTrustNote)
	tail := func(c sessionverify.ChainResult, what string) string {
		if c.TailVerified {
			return "tail verified (" + what + ")"
		}
		return "tail NOT verified"
	}
	l := res.Lock
	fmt.Printf("  NockLock  %-12s %d rows, %s  %s\n", l.Verdict, l.Rows, tail(l, "signed chain_head"), l.Path)
	fmt.Printf("            key %s\n", l.KeyID)
	if l.Reason != "" {
		fmt.Printf("            %s\n", l.Reason)
	}
	g := res.Guard
	fmt.Printf("  NockGuard %-12s %d of %d entries, %s  %s\n", g.Verdict, g.Rows, g.EntriesVerified, tail(g, "signed .hwm covers every entry"), g.Path)
	fmt.Printf("            key %s\n", g.KeyID)
	if g.Reason != "" {
		fmt.Printf("            %s\n", g.Reason)
	}
	fmt.Println(res.RollbackNote)
	fmt.Printf("VERDICT: %s\n", res.Verdict)
}
