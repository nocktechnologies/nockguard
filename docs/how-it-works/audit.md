# Audit and evidence

An enabled audit writes JSONL decisions with a hash chain. Ed25519 signs the
trail when a signing key is configured. Rows include agent, tool, decision,
reason and limited extracted references, never raw arguments or response
payloads. Locally approved decisions may also include the signed
`approval_actor` scalar `local:uid:<decimal>`, sourced from the OS-reported Unix
peer UID. The decimal is canonical and bounded to uint32, and the field is
valid only on `approval-granted` or `approval-denied` rows; verifiers reject
other values. It names an approver uid, not the tool caller, a human, PID, or
executable. Other approval paths omit it. `verify --agent`, `--all`, `--session` and `--export` have distinct
scopes; see the [CLI contract](../specs/cli-policy.md) and
[export proof limits](../verifying-the-trail.md). Rolling back a valid local
trail together with its signed head requires an external anchor to detect.
The field is additive and omitted when unavailable, so pre-existing signed
trail lines continue to verify. Older NockGuard versions cannot validate rows
that carry `approval_actor`; use a verifier that understands the field for new
local-approval rows.
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
[internal/proxy/httplisten.go](../../internal/proxy/httplisten.go), `internal/proxy/required_audit.go`,
[gateway contract](../design/hosted-gateway.md).

`evidence --framework soc2` maps verified rows into a local pack; other
framework names are stubs ([cmd/nockguard/main.go](../../cmd/nockguard/main.go)). Optional NockCC
ops-log forwarding is a second output, not the local proof source
(`internal/forward/forward.go`).
