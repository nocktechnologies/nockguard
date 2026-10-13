# Repository map

Go tests live beside each package as `*_test.go` unless noted otherwise.

| Path | Contents and tests |
| --- | --- |
| `.github/workflows/` | CI, secret scan, review and release workflows; checked in Actions. |
| `cmd/nockguard/` | CLI commands and gateway wiring; CLI, selftest and gateway tests here. |
| `cmd/nockguard-wall/` | Embedded dashboard, NockLock stream and session badges; Wall tests and fixtures here. |
| `cmd/nockguard-pool/` | Pool CLI scaffold; router tests live in `internal/pool/`. |
| `docs/` | Customer, feature, design, contract and operator documentation; reviewed against source and CI. |
| `examples/exfil-demo/` | Poisoned-server demonstration; `run.sh` runs it. |
| `internal/approval/` | Telegram and local-socket approvers; package and proxy end-to-end tests. |
| `internal/audit/` | JSONL writer, hash chain, signatures, checkpoints and exports; package and proxy end-to-end tests. |
| `internal/evidence/` | SOC 2 evidence pack/renderers; package tests and golden fixture. |
| `internal/extract/` | Conservative Nock card reference extraction (PR fields reserved); package tests. |
| `internal/forward/` | Optional NockCC ops-log forwarding; package and proxy tests. |
| `internal/gateway/` | OAuth resource authentication, config and HTTP sessions; package and CLI gateway tests. |
| `internal/jsonrpc/` | MCP JSON-RPC message types; exercised by `internal/proxy/` tests. |
| `internal/policy/` | YAML loader, verdicts, key discovery and shadow rules; package tests including fail-open guards. |
| `internal/pool/` | Pool config, routing and budget logic; package tests. |
| `internal/proxy/` | Stdio/HTTP gates, discovery filtering, required audit and integration tests. |
| `internal/proxy/mcphttp/` | Stdio-to-HTTP bridge with observe-only policy mode and required pre-forward audit when enabled; package end-to-end tests. |
| `internal/proxy/forwardhttp/` | Explicit HTTP/CONNECT egress proxy and SSRF guard; package tests. |
| `internal/ratelimit/` | Sliding-window and session-call caps; package and proxy tests. |
| `internal/secrets/` | Credential reference resolution; package and proxy injection tests. |
| `internal/sessionverify/` | Combined NockLock/NockGuard verdict; caller tests in `cmd/`. |
| `internal/trust/` | Opt-in persisted trust score; package and proxy tests. |
| `internal/validate/` | Argument categories and regexes; package and proxy tests. |
| `livedemo/` | Demo policy and Python client; run manually against a local proxy. |
| `scripts/` | Release helpers and Python quickstart acceptance; quickstart runs in CI. |
| `templates/` | Warden and model API egress project templates; no template-only suite. |
| `AGENTS.md`, `CLAUDE.md` | Bootstrap and contributor map; reviewed against source. |
| `README.md`, `CHANGELOG.md` | Product manual and release history; reviewed against source. |
| `go.mod`, `go.sum`, `LICENSE` | Module, dependencies and MIT license; validated by Go build/test. |

CLI dispatch: [cmd/nockguard/main.go](../cmd/nockguard/main.go). CI gate: [.github/workflows/ci.yml](../.github/workflows/ci.yml).
