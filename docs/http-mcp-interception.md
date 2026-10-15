# HTTP MCP interception

NockGuard supports two paths for an HTTP MCP upstream. Choose the path that
matches the client's connector transport.

## Local stdio client

`nockguard mcp-http` is a stdio-to-HTTP bridge. A client that launches local
stdio MCP servers can run it as the MCP command. It forwards JSON-RPC POSTs to
the configured upstream, preserves the MCP session header, and handles JSON and
SSE responses. This bridge is observe-only: it records tool-call observations
(signed when auditing is configured), but does not block calls by policy. Use
`proxy` for a stdio server or `mcp-listen` for a loopback HTTP client when policy
enforcement is required.

```json
{
  "mcpServers": {
    "example": {
      "command": "nockguard",
      "args": ["mcp-http", "--upstream", "https://mcp.example.com/mcp",
               "--agent", "coder", "--auth-env", "MCP_AUTH_HEADER"]
    }
  }
}
```

Set `MCP_AUTH_HEADER` to the upstream Authorization header value when required.
Use a policy and signing key for `coder` if signed auditing is needed.

To return to a direct connector, restore its previous client configuration and
restart the client. For diagnostics, `NOCKGUARD_TRIPWIRE=1` makes `mcp-http`
forward without audit writes and logs that state loudly at startup; clear the
variable to resume auditing. `--audit-best-effort` allows forwarding after an
audit-write failure and also warns at startup. Both options weaken audit
coverage, so verify the trail after restoring the normal configuration.

## Managed remote HTTP connector

A managed connector sends requests from its provider's infrastructure. It
cannot reach a loopback listener on the operator's machine, and it does not
launch a local stdio command. `mcp-listen` binds loopback and does not
authenticate remote callers. A remote connector therefore needs a reachable,
authenticated HTTPS gateway with a protected route to the listener.

The [listener design](design/n8761-phase0-http-listener-forward-proxy.md)
describes the network boundary and validation requirements. The
[customer-run gateway contract](design/hosted-gateway.md) describes the
implemented OAuth resource, session isolation, and required audit behavior.
