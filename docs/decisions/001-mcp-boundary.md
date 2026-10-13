# 001 — Gate MCP at the transport seam

**Decision.** Wrap stdio servers with `proxy` and offer a separate local HTTP
listener for clients that need HTTP. Filter discovery and gate tool calls at
that seam; leave direct backend API traffic outside the MCP promise.

**Reason.** This keeps the policy tied to the MCP messages NockGuard can
actually inspect. A cloud connector needs a reachable authenticated gateway,
not a loopback listener with a wider bind.

**Consequence.** Operators must wire every intended server through the gate;
network bypasses need separate controls. `mcp-http` remains observe-only.

Sources: [HTTP interception design](../http-mcp-interception.md),
[N8761 correction](../design/n8761-phase0-http-listener-forward-proxy.md),
`internal/proxy/stdio.go`, [cmd/nockguard/main.go](../../cmd/nockguard/main.go).
