// nockguard-pool is the NockGuard pool router (V1 scaffold): it pools
// multiple Codex subscriptions behind one audited localhost endpoint.
// Behavioral contract: docs/POOL_ROUTER.md — anything the binary does that
// the document doesn't describe is a bug.
//
// This scaffold ships config loading + validation only. The proxy/routing
// lane lands in the next piece against the documented contract; until then
// `serve` refuses to start rather than half-routing spend.
package main

import (
	"fmt"
	"os"

	"github.com/nocktechnologies/nockguard/internal/pool"
)

const version = "0.1.0-scaffold"

func usage() {
	fmt.Fprintf(os.Stderr, `nockguard-pool %s — NockGuard pool router (scaffold)

Usage:
  nockguard-pool validate <pool.yaml>   Validate a pool config (loud failures)
  nockguard-pool serve <pool.yaml>      Not yet implemented (scaffold refuses)
  nockguard-pool version                Print version

The full behavioral contract lives in docs/POOL_ROUTER.md.
`, version)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(version)
	case "validate":
		if len(os.Args) != 3 {
			usage()
		}
		cfg, err := pool.Load(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
			os.Exit(1)
		}
		cfg.Normalize()
		fmt.Printf("OK: %d upstream(s), strategy=%s, cooldown=%s, listen=%s\n",
			len(cfg.Pool.Upstreams), cfg.Pool.Routing.Strategy,
			cfg.Pool.Routing.Cooldown(), cfg.Pool.Listen)
		for _, u := range cfg.Pool.Upstreams {
			authPath, err := u.AuthJSONPath()
			if err != nil {
				fmt.Fprintf(os.Stderr, "INVALID: %s: %v\n", u.Label, err)
				os.Exit(1)
			}
			state := "auth.json present"
			if _, statErr := os.Stat(authPath); statErr != nil {
				state = "auth.json MISSING (run codex login in that home)"
			}
			fmt.Printf("  - %s (%s): %s — %s\n", u.Label, u.Provider, u.CodexHome, state)
		}
	case "serve":
		fmt.Fprintln(os.Stderr, "serve: not implemented in the scaffold — the routing lane ships against docs/POOL_ROUTER.md next. Refusing to half-route spend.")
		os.Exit(1)
	default:
		usage()
	}
}
