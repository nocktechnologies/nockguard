# NockGuard contributor guide

## What this repo is

NockGuard is an MCP firewall: a Go CLI that checks tool calls against policy,
records verifiable audit trails, and serves a companion Live Wall dashboard.
Follows Engineering Standards v4.

This is the canonical contributor guide. Source code wins when documentation
and code differ. The [README](README.md) is the product manual;
[docs/ROADMAP.md](docs/ROADMAP.md) tracks the 1.0 bar.

## Task-to-location map

Start with [docs/REPO-MAP.md](docs/REPO-MAP.md) for the full code and test map.
Read the relevant documentation before changing a component.

| To change | Go to | Read first |
| --- | --- | --- |
| CLI commands, selftest, session verification | `cmd/nockguard/` | [README](README.md), [CLI and policy contract](docs/specs/cli-policy.md) |
| Policy keys, validation, rate limits, credentials | `internal/policy/`, `internal/validate/`, `internal/ratelimit/`, `internal/secrets/` | [README](README.md), [policy and limits](docs/how-it-works/policy-and-limits.md) |
| MCP transports and approvals | `internal/proxy/`, `internal/approval/` | [MCP gate](docs/how-it-works/mcp-gate.md), [approvals and injection](docs/how-it-works/approvals-and-injection.md) |
| Audit signing and evidence | `internal/audit/`, `internal/evidence/` | [README](README.md), [audit limits](docs/how-it-works/audit.md) |
| Live Wall | `cmd/nockguard-wall/` | [Wall guide](docs/how-it-works/wall.md) |
| Trust scoring | `internal/trust/` | [Trust](docs/TRUST.md) |
| Pool routing scaffold | `cmd/nockguard-pool/`, `internal/pool/` | [Pool contract](docs/POOL_ROUTER.md) |
| HTTP listener and egress proxy | `internal/proxy/`, `internal/proxy/forwardhttp/` | [Listener and forward-proxy design](docs/design/n8761-phase0-http-listener-forward-proxy.md) |
| Hosted gateway | `internal/gateway/` | [Gateway boundary](docs/design/hosted-gateway.md) |

## Build, test, and required checks

Go tests live beside each package as `*_test.go`. Run focused tests while
working, then the required checks from [.github/workflows/ci.yml](.github/workflows/ci.yml):

```bash
go build ./...
go vet ./...
test -z "$(gofmt -l internal/ cmd/)"
node --test cmd/nockguard-wall/index.test.js
go test -race ./...
python3 scripts/quickstart-acceptance.py
go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
"$(go env GOPATH)/bin/govulncheck" ./...
```

CI also runs `go test -race ./...` on macOS. Keep the fail-open guards and
quickstart acceptance coverage intact; see the README for selftest and coverage
scope. For docs-only changes, check links, documented commands, and consistency
with source; CI remains required before merge.

## Rules that bite

- Unknown agents, malformed tool patterns and unknown validation categories
  must fail closed; keep `internal/policy/*failopen_test.go` green.
- Audit records and the Wall expose decisions and limited references, never
  raw tool arguments or secret values. See [audit limits](docs/how-it-works/audit.md).
- Signing secrets belong in environment variables or protected key files,
  never policy YAML. `keygen` writes private seeds at mode `0600`; the
  [gitleaks workflow](.github/workflows/gitleaks.yml) scans every branch.
- The Wall binds loopback by default. `mcp-listen` rejects non-loopback binds
  in `internal/proxy/httplisten.go`; `mcp-gateway` rejects them in
  `internal/gateway/config.go`. Call out any bind widening in the PR. A remote
  connector needs the separate [gateway boundary](docs/design/hosted-gateway.md).
- `nockguard-pool` is a scaffold; update its [contract](docs/POOL_ROUTER.md)
  with any behavior change.
- Work on a branch, pass CI and merge by PR. Never commit the ignored
  `/nockguard` binary.

## Documentation

- [Customer setup](docs/customer/setup.md) and [CLI and policy contract](docs/specs/cli-policy.md)
- [MCP gate](docs/how-it-works/mcp-gate.md), [policy and limits](docs/how-it-works/policy-and-limits.md), [approvals and injection](docs/how-it-works/approvals-and-injection.md), [audit](docs/how-it-works/audit.md), [Wall](docs/how-it-works/wall.md), [egress proxy](docs/how-it-works/egress-proxy.md)
- [Trust](docs/TRUST.md), [pool status](docs/how-it-works/pool.md) and [contract](docs/POOL_ROUTER.md), [gateway](docs/design/hosted-gateway.md), [runbooks](docs/runbooks/), [decisions](docs/decisions/)
