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

`mcp-http` bridges a stdio client to an HTTP MCP server in observe-only mode;
it is not an enforcement listener ([cmd/nockguard/main.go](../../cmd/nockguard/main.go)). A managed
cloud connector cannot reach an operator's loopback listener. The separate
single-agent `mcp-gateway` needs a customer-supplied OAuth issuer and reachable
HTTPS ingress. See the [gateway contract](../design/hosted-gateway.md) and
[N8761 transport design](../design/n8761-phase0-http-listener-forward-proxy.md).

Direct backend API calls and unwrapped MCP servers bypass this gate. See the
[README coverage scope](../../README.md#coverage-scope).
