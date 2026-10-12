# NockGuard contributor map

Start with [docs/REPO-MAP.md](docs/REPO-MAP.md) for code and test locations. The
[README](README.md) is the product manual; [docs/ROADMAP.md](docs/ROADMAP.md)
tracks the 1.0 bar. Source code wins when documentation and code differ.

## Build and test

```bash
go build ./...
go vet ./...
test -z "$(gofmt -l internal/ cmd/)"
go test -race ./...
python3 scripts/quickstart-acceptance.py
```

CI runs these in [.github/workflows/ci.yml](.github/workflows/ci.yml).

## Rules that bite

- Unknown agents, malformed tool patterns and unknown validation categories
  must fail closed; keep `internal/policy/*failopen_test.go` green.
- Audit records and the Wall expose decisions and limited references, never
  raw tool arguments or secret values. See [audit limits](docs/how-it-works/audit.md).
- Signing secrets belong in environment variables or protected key files,
  never policy YAML. `keygen` writes private seeds at mode `0600`; the
  [gitleaks workflow](.github/workflows/gitleaks.yml) scans every branch.
- The Wall binds loopback by default; `mcp-listen` and `mcp-gateway` require
  explicit loopback addresses. A remote connector needs the separate
  [gateway boundary](docs/design/hosted-gateway.md).
- `nockguard-pool` is a scaffold; update its [contract](docs/POOL_ROUTER.md)
  with any behavior change.
- Work on a branch, pass CI and merge by PR. Never commit the ignored
  `/nockguard` binary.

## Documentation

- [Customer setup](docs/customer/setup.md) and [CLI and policy contract](docs/specs/cli-policy.md)
- [MCP gate](docs/how-it-works/mcp-gate.md), [policy and limits](docs/how-it-works/policy-and-limits.md), [approvals and injection](docs/how-it-works/approvals-and-injection.md), [audit](docs/how-it-works/audit.md), [Wall](docs/how-it-works/wall.md), [egress proxy](docs/how-it-works/egress-proxy.md)
- [Trust](docs/TRUST.md), [pool status](docs/how-it-works/pool.md) and [contract](docs/POOL_ROUTER.md), [gateway](docs/design/hosted-gateway.md), [runbooks](docs/runbooks/), [decisions](docs/decisions/)
