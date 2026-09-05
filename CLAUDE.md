# nockguard — repo map

MCP firewall for AI agent fleets: a Go proxy that sits between an agent and its
MCP servers, checks every `tools/list` / `tools/call` against a per-agent YAML
policy, and writes an append-only, hash-chained (optionally Ed25519-signed)
audit trail of every decision. Three binaries — `nockguard` (the gate),
`nockguard-wall` (live dashboard), `nockguard-pool` (Codex subscription router,
scaffold) — plus Claude Code project templates. Sibling product to `nocklock`
(secret isolation); same brand, independent tools. Pointers only; if this map
and a live source disagree, the live source wins.

## Where things are
| Path | What |
|---|---|
| `cmd/nockguard/` | the CLI: `init`, `proxy`, `mcp-http`, `mcp-listen`, `egress-proxy`, `verify`, `selftest`, `policy`, `evidence`, `keygen`, `trust`. `printUsage()` in `main.go` is the authoritative command surface |
| `cmd/nockguard-wall/` | Live Wall: tails the audit JSONL, streams decisions to an embedded loopback dashboard |
| `cmd/nockguard-pool/` | pool router scaffold; its behavioral contract is `docs/POOL_ROUTER.md` |
| `internal/policy/` | policy load + validation and the verdict engine (deny → ask → allow/mode) |
| `internal/proxy/` | the stdio and HTTP gates real traffic passes through; the end-to-end tests live here |
| `internal/audit/` | append-only JSONL trail, HMAC hash-chain, Ed25519 signing, checkpoints, verify |
| `internal/validate/`, `ratelimit/`, `trust/`, `approval/`, `evidence/`, `forward/` | argument validation, sliding-window limit + spend cap, behavioral trust score, human approval gate, compliance evidence packs, NockCC ops-log forwarding |
| `README.md` | the manual: every policy key, audit/signing modes, `selftest`, coverage scope, roadmap |
| `docs/` | `TRUST.md` (score model), `POOL_ROUTER.md` (contract), `http-mcp-interception.md` and `design/n8761-*` (HTTP interception; the design note supersedes the older one) |
| `templates/` | Claude Code project templates shipped to users (`warden/`, `egress/`) — their `CLAUDE.md` files are payload for downstream repos, not this repo's map |
| `livedemo/` | demo policy + Python client used to show the firewall blocking live |

## Run and test
```bash
go build ./...
go test -race ./...            # the CI gate
gofmt -l internal/ cmd/        # must print nothing
go vet ./...
```

## Where it runs
- Per agent, on the operator's machine: `nockguard proxy --upstream "<mcp server cmd>" --agent <name>` wired in as that MCP server's command. Runtime state lives in `~/.nockguard/` — `policy.yaml`, `logs/<agent>.audit.jsonl`, `trust/<agent>.json`.
- Live Wall: `go run ./cmd/nockguard-wall` → `http://127.0.0.1:8787` (loopback).
- Distribution is a binary, not a deploy: `brew install nocktechnologies/tap/nockguard` or `go install github.com/nocktechnologies/nockguard/cmd/nockguard@latest`.
- Fleet dogfood target is Mira's NockCC connection; its status and the Kevin-gated cutover are in `docs/design/n8761-phase0-http-listener-forward-proxy.md`.

## Rules that bite
- Fail closed. An unknown agent, a malformed glob, or an unknown `validate_input` category must DENY, never quietly pass — `internal/policy/policy.go` plus the `*_failopen_test.go` guards.
- The audit trail and the wall record the decision only (agent, tool, outcome, reason) — never tool-call arguments or payloads (`internal/audit/audit.go`, README "Live Wall").
- Signing keys are read from env vars only: never written into `policy.yaml`, never committed. `gitleaks` scans every branch against `.gitleaks-baseline.json`.
- Listeners bind loopback by default (wall, `mcp-listen`, pool router); do not widen a bind without saying so in the PR.
- Anything `nockguard-pool` does that `docs/POOL_ROUTER.md` does not describe is a bug — change the contract in the same PR as the behavior.
- Work on a branch and merge by PR with CI green (gofmt, vet, build, `-race` tests, gitleaks). Never commit the built `/nockguard` binary; it is gitignored on purpose.
