# NockGuard contributor guide

This is the index for every agent and contributor working in this repo. Read
`docs/HANDOFF.md` first, and add to it before you finish. Source code wins
when this file and code differ.

## What this repo is

NockGuard is an MCP firewall: a single Go binary that sits between an MCP
client and an MCP server, checks each tool call against a YAML policy, writes
a hash-chained, optionally Ed25519-signed audit trail, and serves a companion
Live Wall dashboard (`cmd/nockguard-wall/`). It is MIT, works offline, and has
no phone-home or license gate. Follows Engineering Standards v4.

- Product manual: `README.md`
- Code and test map: `docs/REPO-MAP.md`
- Architecture: `docs/how-it-works/mcp-gate.md` and the decision records in `docs/decisions/`
- Changelog: `CHANGELOG.md`
- Roadmap and the 1.0 bar: `docs/ROADMAP.md`
- Contributor rules for humans: `CONTRIBUTING.md`; vulnerability reports: `SECURITY.md`

## Build and test

Go is pinned in `go.mod`; the Wall browser tests need Node 22. Go tests live
beside each package as `*_test.go`. Run focused tests while working, then
every CI step before you open a PR:

```bash
python3 scripts/check-agents-paths.py          # every path named in AGENTS.md is git-tracked
node --test cmd/nockguard-wall/index.test.js   # Wall browser tests
test -z "$(gofmt -l internal/ cmd/)"           # gofmt
go vet ./...
go build ./...
go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
"$(go env GOPATH)/bin/govulncheck" ./...
go test -race ./...
python3 scripts/quickstart-acceptance.py       # README quickstart end to end; Linux only
```

These are the `build-test` job steps in `.github/workflows/ci.yml`; the same
workflow runs `go test -race ./...` on macOS as `macos-test`. The test suite
needs no external services and there are no generated files.

Before opening a PR, run the firewall's own proof against a policy that names
your agent:

```bash
go run ./cmd/nockguard selftest --policy <your-policy.yaml>
```

Closeout: maintainers gate the automated two-model review and the
`CodeRabbit`, `build-test`, `macos-test`, `claude-review`
(`.github/workflows/claude-code-review.yml`), and `scan`
(`.github/workflows/gitleaks.yml`, every branch) checks on the exact PR head.
A new commit needs fresh checks and review.

## Branches and releases

- Product PRs branch from and target `next`, one issue or tracking card per
  PR. `main` receives squash-promoted releases and is back-synced into
  `next` after each tag. Never merge to `main` yourself.
- Do not touch the release flow without a maintainer. It is in
  `docs/runbooks/release.md`: freeze `next`, promote by squash PR, tag from
  `main`, back-sync `main` into `next`.
- The release version is hardcoded in `cmd/nockguard/main.go` and must move
  with `docs/ROADMAP.md` and the `CHANGELOG.md` heading;
  `scripts/check-release-version.sh` rejects a mismatch.
- Every behavior change gets a `CHANGELOG.md` entry under `[Unreleased]` and a
  test. Policy-engine changes need a table-driven case in `internal/policy/`;
  audit-format changes need a round trip through `verify`.

## Rules that bite

- Fail closed. Unknown agents, malformed tool patterns and unknown validation
  categories must be denied; keep `internal/policy/glob_failopen_test.go` and
  `internal/policy/validate_category_failopen_test.go` green. A `verify` that
  cannot prove a trail exits non-zero; a selftest that proves nothing fails.
- Audit records and the Wall expose decisions and limited references, never
  raw tool arguments, response payloads or secret values. See
  `docs/how-it-works/audit.md`.
- Signing secrets belong in environment variables or protected key files,
  never policy YAML. Keys are `NOCKGUARD_AUDIT_KEY` (HMAC),
  `NOCKGUARD_AUDIT_ED25519_KEY` and `NOCKGUARD_AUDIT_ED25519_PUB`, or per agent
  `NOCKGUARD_AGENT_<NAME>_ED25519_KEY` and `NOCKGUARD_AGENT_<NAME>_ED25519_PUB`.
  `keygen` writes private seeds at mode `0600`. Public keys verify; private
  keys sign. Anything that lets a verifier forge an entry is a bug.
- Never commit keys, seeds, audit logs, anything under `~/.nockguard`, or the
  ignored root `nockguard` binary. The gitleaks baseline is
  `.gitleaks-baseline.json`.
- The Wall binds loopback by default. `mcp-listen` rejects non-loopback binds
  in `internal/proxy/httplisten.go`; `mcp-gateway` rejects them in
  `internal/gateway/config.go`. Call out any bind widening in the PR. A remote
  connector needs the separate gateway boundary in `docs/design/hosted-gateway.md`.
- `mcp-http` (`internal/proxy/mcphttp/`) is observe-only: it audits but never
  blocks. Enforcement is `proxy` (stdio) or `mcp-listen` (loopback HTTP).
- Forwarding to any external system is opt-in and fail-open, and nothing may
  need the network to function.
- `nockguard-pool` is a scaffold; update `docs/POOL_ROUTER.md` with any
  behavior change.
- `.claude/commands/` is the source for the policy-lint, vuln-scan and
  threat-model slash commands. `templates/warden/.claude/commands/` must hold
  byte-identical copies; `cmd/nockguard/helper_templates_test.go` enforces
  that and keeps the lint key list in step with the policy loader.
- `NOCKGUARD_APPROVAL_TEST=approve|deny` is the e2e approval test seam
  (`internal/approval/approval.go`); never rely on it outside tests.

## Where things are

| To change | Go to | Read first |
| --- | --- | --- |
| CLI commands, selftest, session verification | `cmd/nockguard/`, `internal/sessionverify/` | `docs/specs/cli-policy.md` |
| Policy keys, validation, rate limits, credentials | `internal/policy/`, `internal/validate/`, `internal/ratelimit/`, `internal/secrets/` | `docs/how-it-works/policy-and-limits.md` |
| MCP transports and approvals | `internal/proxy/`, `internal/approval/` | `docs/how-it-works/mcp-gate.md`, `docs/how-it-works/approvals-and-injection.md` |
| Audit signing and evidence | `internal/audit/`, `internal/evidence/` | `docs/how-it-works/audit.md`, `docs/verifying-the-trail.md` |
| Live Wall | `cmd/nockguard-wall/` | `docs/how-it-works/wall.md` |
| Trust scoring | `internal/trust/` | `docs/TRUST.md` |
| Pool routing scaffold | `cmd/nockguard-pool/`, `internal/pool/` | `docs/POOL_ROUTER.md` |
| HTTP listener and egress proxy | `internal/proxy/`, `internal/proxy/forwardhttp/` | `docs/how-it-works/egress-proxy.md`, `docs/design/n8761-phase0-http-listener-forward-proxy.md` |
| Hosted gateway | `internal/gateway/` | `docs/design/hosted-gateway.md` |
| Customer setup and templates | `docs/customer/setup.md`, `templates/`, `livedemo/` | `README.md` |
| Incidents and releases | `docs/runbooks/` | `docs/runbooks/incident.md`, `docs/runbooks/release.md` |

## Docs upkeep

- Keep this file about 100-150 lines. Gotchas stay here; long material gets
  its own file and one line above.
- Name repo files as plain paths in backticks.
  `scripts/check-agents-paths.py` fails CI when one is not git-tracked; write
  example file names as a `<placeholder>`.
- Move stale docs and dated handoffs to `docs/archive/` instead of deleting them.
