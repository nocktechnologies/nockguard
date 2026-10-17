# MCP gate and transport boundary

`proxy` wraps one stdio MCP server. It filters `tools/list` and checks
`tools/call` before forwarding. Other method-bearing messages pass through by
default, with a distinct `method-allow` or `method-deny` audit decision recording the method name in `tool` and no
params when auditing is enabled. Per-agent `deny_methods` refuses exact method
names before upstream contact, including notification forms (silently dropped).
Tool allow/deny patterns, argument validation, approvals and limits apply only
to `tools/call`; they do not inspect `resources/read`, `prompts/get` or
`completion/complete` params. `tools/list` still filters discovered tools.
Responses without a method are forwarded without a method audit row. A missing
policy file starts zero-config observe mode only when `--policy` was not
supplied. An unknown agent in a loaded policy has no permissions unless
`default` covers it. `mcp-listen` applies the shared gate to a local HTTP
listener. Source: `internal/proxy/stdio.go`, `internal/proxy/httplisten.go`,
[cmd/nockguard/main.go](../../cmd/nockguard/main.go).

In opt-in stdio action-pairing mode, a complete client `tools/list` pagination
chain builds the observed definition catalog. Signed v2 call rows carry observed
hashes only from a complete single-page listing. A completed paginated catalog
is kept, but later calls stay `unobserved` with no hash, because raw upstream
cursors can be reused across listings. A new first-page listing or
`notifications/tools/list_changed` drops the catalog. After that, a fresh
complete single-page listing restores observed hashes; a paginated one does
not. The digest identifies an advertised definition, not the server's behavior.
See [audit](audit.md) for the signed fields and limits.

Operator pins are configured per agent, stable upstream ID, and exact tool
name. Pass `--upstream-id` to `proxy`; a configured pin always gates discovery
and direct calls, while `strict_tool_pins` additionally requires a pin for every
allowed tool. Re-list after `notifications/tools/list_changed`; a paginated
catalog cannot authorize pinned calls. See [policy and limits](policy-and-limits.md).
The final pin check and durable dispatch are serialized with catalog changes.
A call dispatched before `list_changed` remains in flight, even if the upstream
write completes afterward; later calls require a fresh verified listing.
`mcp-http`, `mcp-listen`, and `mcp-gateway` refuse pin policies until HTTP catalog
observations can be bound to individual upstream sessions.

`mcp-http` bridges a stdio client to an HTTP MCP server in observe-only mode;
it is not an enforcement listener ([cmd/nockguard/main.go](../../cmd/nockguard/main.go)). A managed
cloud connector cannot reach an operator's loopback listener. The separate
single-agent `mcp-gateway` needs a customer-supplied OAuth issuer and reachable
HTTPS ingress. See the [gateway contract](../design/hosted-gateway.md) and
[N8761 transport design](../design/n8761-phase0-http-listener-forward-proxy.md).

Direct backend API calls and unwrapped MCP servers bypass this gate. See the
[README coverage scope](../../README.md#coverage-scope).
