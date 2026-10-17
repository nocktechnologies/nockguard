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

The stdio writer has an opt-in schema v2 action-pairing mode:

```yaml
audit:
  enabled: true
  action_pairing: true
```

It assigns a fresh run nonce and an increasing action sequence before policy
evaluation. Decision rows and the required dispatch share that `action_id`; a
matching JSON-RPC response produces `response_observed`, while timeout,
cancellation, disconnect, and shutdown produce `outcome_unknown`. A late reply
after an unknown outcome is appended as `late_response_observed`, preserving
the original uncertainty. No request IDs, tool arguments, or response bodies
are written. Audit verification accepts historical v1 rows with their original
typed-marshal signature bytes and strictly validates v2 rows; old binaries
cannot verify signed v2 trails, and their signed writer refuses to reopen such
a trail after startup verification fails. An older unsigned writer does not
authenticate v2 fields and may append legacy rows instead. Keep pairing on a
dedicated audit path; a rollback must use a new path. Pairing is disabled by
default, requires required audit writes, applies to stdio only, and cannot be
combined with `--audit-best-effort`. These action rows do not include run
open/close records and therefore do not support a completeness verdict; the
dispatch itself never proves execution or success. Source:
`internal/audit/audit.go`, `internal/proxy/stdio.go`.

With pairing enabled, a complete client-initiated `tools/list` pagination chain
publishes a session catalog. Each advertised full tool definition receives a
versioned RFC 8785 SHA-256 digest. Applicable v2 decision and observation rows
sign `tool_hash_version`, `tool_definition_hash`, and `tool_pin_status`:
`unpinned` for a hashable observed definition, `unobserved` before a complete
listing or after `notifications/tools/list_changed`, and `unhashable` when a
definition has ambiguous keys, invalid shape, or an unsupported number. A
failed, repeated, or oversized page discards the incomplete catalog. No raw
definition or schema is written to the trail. This records the definition the
server advertised; it does not establish how the server behaved when called.
In observation-only mode, raw upstream cursors can be reused across listing
generations, so even a completed paginated catalog leaves later calls
`unobserved` without an attached digest. A single page complete listing can
bind its observed digest to later calls.
An operator can configure `tool_pins` by stable upstream ID and exact tool name.
Run the stdio proxy with the matching `--upstream-id`. Pin policies require a
signing key and `audit.action_pairing: true`; `--audit-best-effort` is refused.
The signed action rows then carry both `tool_pin_hash` (expected) and
`tool_definition_hash` (observed), with `matched`, `mismatch`, `unobserved`,
`unhashable`, or `unpinned` status. Re-listing only changes the observed hash.
An ordinary call approval cannot update a pin. A mismatch or unverified pinned
tool is hidden from `tools/list` and blocked on direct `tools/call`, even with
strict mode off. `strict_tool_pins: true` also blocks unpinned tools.
After `notifications/tools/list_changed`, re-list from the first page or
reconnect before calling a pinned tool. A paginated catalog remains unverified
for later calls because upstream cursors can be reused; pinned tools are hidden
from such a listing and direct pinned calls stay blocked. The current verified
catalog is stdio-scoped. A call with a durable dispatch row before
`list_changed` remains in flight; invalidation blocks subsequent calls.

When pairing is enabled, the writer resumes unsigned `run_seq` counters from
valid v2 rows already in the trail. Unsigned audit opens without pairing retain
the legacy path and do not scan the trail for sequence state.

`evidence --framework soc2` maps verified rows into a local pack; other
framework names are stubs ([cmd/nockguard/main.go](../../cmd/nockguard/main.go)). Optional NockCC
ops-log forwarding is a second output, not the local proof source
(`internal/forward/forward.go`).
