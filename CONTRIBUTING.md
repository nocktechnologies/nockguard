# Contributing to NockGuard

Thanks for looking. NockGuard is small on purpose: a single Go binary that sits between an MCP client and an MCP server, enforces a policy, and writes a signed audit trail. Changes that keep it small, boring, and provable are the ones that land.

## Ground rules

- **Fail closed.** An agent with no policy is denied. A verify that cannot prove a trail returns non-zero. A selftest that proves nothing does not pass. Keep that shape in anything you add.
- **The audit trail never carries payloads.** Decisions (agent, tool, outcome, reason) are recorded; tool-call arguments are not. Do not add them.
- **No phone-home, no license gate.** Everything in this repository is MIT and stays functional offline. Forwarding to any external system is opt-in and fail-open.
- **Public keys verify; private keys sign.** Anything that would let a verifier forge an entry is a bug.

## Development

```bash
go build ./...
go test ./...
go vet ./...
```

Go version is pinned in `go.mod`. There are no generated files and no external services required for the test suite.

Before opening a pull request, run the firewall's own proof against a policy that names your agent:

```bash
go run ./cmd/nockguard selftest --policy policy.yaml
```

## Pull requests

- One change per PR, with the reason in the description — what a user could not do before, or what could go wrong before.
- Add or update a test for every behavior change. Policy-engine changes need a table-driven case in `internal/policy`; audit-format changes need a round-trip through `verify`.
- Update `CHANGELOG.md` under the unreleased heading.
- Do not commit keys, seeds, audit logs, or anything under `~/.nockguard`. `gitleaks` runs on every PR; the baseline is `.gitleaks-baseline.json`.
- PRs are reviewed by maintainers and an automated two-model review; both must be clean at the exact head that merges.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not open a public issue for a vulnerability.

## License

By contributing you agree that your contributions are licensed under the MIT license in `LICENSE`.
