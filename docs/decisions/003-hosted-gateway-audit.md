# 003 — Require audit before hosted forwarding

**Decision.** The customer-run `mcp-gateway` requires an enabled per-agent
Ed25519 audit and syncs a dispatch decision before forwarding a tool call.
Stdio `proxy` and local `mcp-listen` retain their existing best-effort audit
behavior for now.

**Reason.** A remote authenticated route needs a durable local record before
it authorizes a tool. The dispatch record proves authorization to forward,
not remote execution.

**Consequence.** A gateway writer failure stops new requests until storage is
repaired and the process restarts. An error after forwarding requires upstream
inspection before retry. The 1.0 roadmap still calls for fail-closed local
audit outside this gateway.

Sources: [0.3.0 changelog](../../CHANGELOG.md#030---2026-10-01),
[gateway contract](../design/hosted-gateway.md),
`internal/proxy/required_audit.go`, `internal/proxy/stdio.go`.

**2026-10-13 update — superseded in part.** Local stdio `proxy`, `mcp-listen`,
and `mcp-http` now require an audit write before forwarding tool calls when
auditing is enabled and refuse calls on required-writer failure. Operators can
explicitly choose the former behavior with `--audit-best-effort`. The hosted
gateway requirement and recovery contract above still apply.
