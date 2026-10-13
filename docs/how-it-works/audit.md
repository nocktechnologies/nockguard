# Audit and evidence

An enabled audit writes JSONL decisions with a hash chain. Ed25519 signs the
trail when a signing key is configured. Rows include agent, tool, decision,
reason and limited extracted references, never raw arguments or response
payloads. `verify --agent`, `--all`, `--session` and `--export` have distinct
scopes; see the [CLI contract](../specs/cli-policy.md) and
[export proof limits](../verifying-the-trail.md). Rolling back a valid local
trail together with its signed head requires an external anchor to detect.
Source: `internal/audit/audit.go`, `internal/audit/export.go`.

Local `proxy` and `mcp-listen` require a durable `dispatch` row before
forwarding a tool call. Deferred decisions are written in request order, so an
out-of-order response can be released before its decision row is written. A
later write failure latches the writer and refuses later calls until repair and
verified reopen. The failure marker is per trail: any verified reopen clears
it, even while another process using that trail remains latched and keeps
refusing calls. `--audit-best-effort` explicitly restores local forwarding
after audit-write errors. `mcp-http` writes its observe decision before forwarding.
`mcp-gateway` also requires synced audit records and stops new requests after
a write failure until repair and restart. A dispatch row proves permission to
forward, not execution. If failure occurs after forwarding, inspect upstream
state before retrying. Source: `internal/proxy/stdio.go`,
`internal/proxy/httplisten.go:246`, `internal/proxy/required_audit.go`,
[gateway contract](../design/hosted-gateway.md).

`evidence --framework soc2` maps verified rows into a local pack; other
framework names are stubs (`cmd/nockguard/main.go:1003`). Optional NockCC
ops-log forwarding is a second output, not the local proof source
(`internal/forward/forward.go`).
