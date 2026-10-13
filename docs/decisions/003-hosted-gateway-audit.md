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
