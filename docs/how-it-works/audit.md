# Audit and evidence

An enabled audit writes JSONL decisions with a hash chain. Ed25519 signs the
trail when a signing key is configured. Rows include agent, tool, decision,
reason and limited extracted references, never raw arguments or response
payloads. `verify --agent`, `--all`, `--session` and `--export` have distinct
scopes; see the [CLI contract](../specs/cli-policy.md) and
[export proof limits](../verifying-the-trail.md). Rolling back a valid local
trail together with its signed head requires an external anchor to detect.
Source: `internal/audit/audit.go`, `internal/audit/export.go`.

Stdio `proxy` and local `mcp-listen` still log an audit write error and may
continue forwarding. `mcp-gateway` requires a synced `dispatch` row before
forwarding and synced deferred decisions before releasing results. Its writer
failure stops new requests until repair and restart. A dispatch row proves
permission to forward, not execution. If failure occurs after forwarding,
inspect upstream state before retrying. Source: `internal/proxy/stdio.go`,
`internal/proxy/httplisten.go:246`, `internal/proxy/required_audit.go`,
[gateway contract](../design/hosted-gateway.md).

`evidence --framework soc2` maps verified rows into a local pack; other
framework names are stubs (`cmd/nockguard/main.go:1003`). Optional NockCC
ops-log forwarding is a second output, not the local proof source
(`internal/forward/forward.go`).
