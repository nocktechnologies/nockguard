# Contributing to NockGuard

Thanks for looking. NockGuard is small on purpose: a single Go binary that sits between an MCP client and an MCP server, enforces a policy, and writes a signed audit trail. Changes that keep it small, boring, and provable are the ones that land.

## Ground rules

- **Fail closed.** An agent with no policy is denied. A verify that cannot prove a trail returns non-zero. A selftest that proves nothing does not pass. Keep that shape in anything you add.
- **The audit trail never carries payloads.** Decisions (agent, tool, outcome, reason) are recorded; tool-call arguments are not. Do not add them.
- **No phone-home, no license gate.** Everything in this repository is MIT and stays functional offline. Forwarding to any external system is opt-in and fail-open.
- **Public keys verify; private keys sign.** Anything that would let a verifier forge an entry is a bug.

## Development

Before you push, run the tests for the packages you touched, plus lint. CI runs the full suite once as the gate, so you do not need to run it locally:

```bash
go test -race ./internal/<package>/ ./cmd/<command>/   # only the packages you touched
test -z "$(gofmt -l internal/ cmd/)" && go vet ./...   # lint
node --test cmd/nockguard-wall/index.test.js           # if you touched the Wall (Node 22)
```

CI runs `go build ./...`, `go vet ./...`, gofmt, `go test -race ./...`, the Wall browser tests, `scripts/quickstart-acceptance.py` (Linux only), `govulncheck ./...` and the `gitleaks` secret scan. A PR that changes only Markdown or `docs/` skips the suite and runs only the tests that read repo Markdown. Go version is pinned in `go.mod`. There are no generated files and no external services required for the test suite.

Before opening a pull request, run the firewall's own proof against a policy that names your agent:

```bash
go run ./cmd/nockguard selftest --policy policy.yaml
```

## Pull requests

- Keep each PR focused on one issue or internal tracking card and target `next`, with the reason in the description — what a user could not do before, or what could go wrong before.
- Add or update a test for every behavior change. Policy-engine changes need a table-driven case in `internal/policy`; audit-format changes need a round-trip through `verify`.
- Update `CHANGELOG.md` under the unreleased heading.
- Do not commit keys, seeds, audit logs, or anything under `~/.nockguard`. `gitleaks` runs on every PR; the baseline is `.gitleaks-baseline.json`.
- Maintainers gate an automated two-model review and the `CodeRabbit`, `build-test`, `macos-test`, `claude-review`, and `scan` checks at the exact PR head. A passing or skipped check is not a substitute for reviewing the findings. A new commit needs fresh checks and review before merge. The `ci` workflow also runs the Linux and macOS checks on pushes to both `next` and `main`.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not open a public issue for a vulnerability.

## License

By contributing you agree that your contributions are licensed under the MIT license in `LICENSE`.
