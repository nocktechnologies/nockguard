# Road to 1.0

The five release gates approved for 1.0 are tracked here against the source on
this branch. A gate marked implemented has code and verification in place;
other statuses describe remaining work. Version is `v0.8.0` in
`cmd/nockguard/main.go`.

| Gate | Current evidence and remaining work |
| --- | --- |
| 1. Fail-closed local audit (N11644) | **Implemented in source.** With auditing enabled, stdio `proxy`, local `mcp-listen`, and `mcp-http` refuse tool calls when the required audit cannot be written; `--audit-best-effort` explicitly restores forwarding on local transports. `mcp-gateway` requires durable audit without that opt-out. See `internal/proxy/required_audit.go`, `internal/proxy/stdio.go`, [audit boundary](how-it-works/audit.md). |
| 2. macOS tests green in CI (N11648) | **Implemented and verified in CI.** [.github/workflows/ci.yml](../.github/workflows/ci.yml) runs `go test -race ./...` on `macos-latest` as well as `ubuntu-latest`. |
| 3. Wall bundled and key discovery fixed (N11645) | **Released in v0.6.0.** `nockguard wall` launches the companion binary; Homebrew installs both binaries, and the release archives contain both. See [Install](../README.md#install) and [the Wall guide](how-it-works/wall.md). |
| 4. Quickstart proven end to end in CI (N11647) | **Implemented for the Linux stub route.** [.github/workflows/ci.yml](../.github/workflows/ci.yml) runs `scripts/quickstart-acceptance.py`, including allowed and denied calls and signed verification. It does not certify a hosted customer connector. |
| 5. CLI, policy schema and exit codes documented as a kept contract | **Written for review** in [CLI and policy contract](specs/cli-policy.md), sourced from [cmd/nockguard/main.go](../cmd/nockguard/main.go), [internal/policy/policy.go](../internal/policy/policy.go), [cmd/nockguard/selftest.go](../cmd/nockguard/selftest.go) and [cmd/nockguard/verify_session.go](../cmd/nockguard/verify_session.go). Keep it current as behavior changes. |

1.0 requires all five gates to be complete and verified in CI or the stated
customer check. The [release runbook](runbooks/release.md) records the current
packaging and version gates.
