# MCP gate and transport boundary

`proxy` wraps one stdio MCP server. It filters `tools/list` and checks
`tools/call` before forwarding; other MCP messages pass through. A missing
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
