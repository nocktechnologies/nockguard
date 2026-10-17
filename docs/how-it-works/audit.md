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
default, requires signed and durable audit writes, applies to stdio only, and cannot be
combined with `--audit-best-effort`. The signed producer durably appends
`run/open` before accepting calls, writes `run/heartbeat` every 30 seconds,
and writes `run/close` after its bounded shutdown drain only if the writer
stayed healthy. The close commits the preceding per-run count and signature
under the shared trail's file lock. `verify --completeness` reports a separate
per-run assessment after ordinary integrity verification. `LIMITED` means
only that the signed observation stream recorded for that run is internally
complete; it does not certify every attempt was recorded or that an upstream
side effect completed. A missing close becomes `INCOMPLETE` after 90 seconds
without a heartbeat, but cannot distinguish a crash from a cut trail. Recent
open runs are `IN_PROGRESS`, future-dated heartbeats are `UNASSESSABLE`,
legacy trails are `UNVERIFIED`, and invalid run structure is `BROKEN`. The
dispatch itself never proves execution or success. Source:
`internal/audit/audit.go`, `internal/proxy/stdio.go`.

When pairing is enabled, the writer resumes unsigned `run_seq` counters from
valid v2 rows already in the trail. Unsigned audit opens without pairing retain
the legacy path and do not scan the trail for sequence state.

`evidence --framework soc2` maps verified rows into a local pack; other
framework names are stubs ([cmd/nockguard/main.go](../../cmd/nockguard/main.go)). Optional NockCC
ops-log forwarding is a second output, not the local proof source
(`internal/forward/forward.go`).
