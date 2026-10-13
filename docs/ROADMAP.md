# Road to 1.0

The five release gates approved for 1.0 are tracked here against the source on
this branch. A gate marked implemented has code and verification in place;
other statuses describe remaining work. Version remains `v0.5.0` in
`cmd/nockguard/main.go:94`.

| Gate | Current evidence and remaining work |
| --- | --- |
| 1. Fail-closed local audit (N11644) | **Open.** `mcp-gateway` has required durable audit, but stdio `proxy` and local `mcp-listen` still log writer failures and may forward. See `internal/proxy/required_audit.go`, `internal/proxy/stdio.go`, [audit boundary](how-it-works/audit.md). |
| 2. macOS tests green in CI (N11648) | **Open.** `.github/workflows/ci.yml:13` runs on `ubuntu-latest` only. Add a macOS job and require green results. |
| 3. Wall bundled and key discovery fixed (N11645) | **Implemented in source; release pending.** `nockguard wall` launches the companion binary, and `scripts/build-release-assets.sh` packages both. Published v0.5.0 archives and the Homebrew formula predate this change; the next release and formula update must deliver it. See [the Wall guide](how-it-works/wall.md). |
| 4. Quickstart proven end to end in CI (N11647) | **Implemented for the Linux stub route.** `.github/workflows/ci.yml:40` runs `scripts/quickstart-acceptance.py`, including allowed and denied calls and signed verification. It does not certify a hosted customer connector. |
| 5. CLI, policy schema and exit codes documented as a kept contract | **Written for review** in [CLI and policy contract](specs/cli-policy.md), sourced from `cmd/nockguard/main.go:81`, `internal/policy/policy.go:23`, `cmd/nockguard/selftest.go:64` and `cmd/nockguard/verify_session.go:119`. Keep it current as behavior changes. |

1.0 requires all five gates to be complete and verified in CI or the stated
customer check. The [release runbook](runbooks/release.md) records the current
packaging and version gates.
