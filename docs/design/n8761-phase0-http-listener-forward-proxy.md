# N8761 — HTTP Listener and Hosted Connector Deployment

Status: the local `mcp-listen` implementation exists. Hosted-connector deployment
is incomplete. This revision corrects the original Phase-0 assumption that a
managed `claude.ai` connector could point directly to the operator's loopback
listener. No live connector change is part of this document.

This supersedes the flagship-seat transport guidance in
[`http-mcp-interception.md`](../http-mcp-interception.md). Historical pilot
observations in that note are not a current deployment-health check.

## Network boundary

Anthropic's [remote connector network requirements](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp)
state that managed connectors connect from Anthropic's cloud, including when the
user runs Claude Desktop or Cowork. The endpoint must be reachable from that
infrastructure. Reviewed 2026-09-26.

Consequently, `http://127.0.0.1:8790/mcp` on the operator's machine is **not a
hosted connector endpoint**. URL validation, a locally trusted certificate,
and successfully calling the listener from the operator's laptop do not prove
cloud reachability. Local stdio MCP configuration is a separate transport.

## Existing local implementation

| Component | Responsibility |
| --- | --- |
| `cmd/nockguard/main.go` (`mcp-listen`) | Load one agent's policy, signing key, validation, limits and approver |
| `internal/proxy/httplisten.go` | Loopback POST listener, canonical request gate, upstream forwarding and session/protocol headers |
| `internal/proxy/stdio.go` | Shared tool policy, validation, rate/spend limits, approvals and discovery filtering |
| `internal/proxy/tool_discovery_http.go` | Filter JSON and SSE tool listings while preserving pagination and metadata |
| `internal/audit` | Signed decision trail; tool arguments and authorization headers are excluded |

A local client can call this listener directly. For example:

```bash
nockguard mcp-listen --listen 127.0.0.1:8790 \
  --upstream https://mcp.example.com/mcp --agent coder --policy policy.yaml
```

The process has a configured agent identity; it does not authenticate a remote
caller as that agent. Passing an inbound `Authorization` header to the upstream
is not an authentication or identity boundary for NockGuard itself.

## Proposed hosted topology

```text
Managed Claude connector (Anthropic cloud)
  -> reachable HTTPS gateway with connector authentication
  -> protected route to the selected agent's loopback listener
  -> NockGuard policy and audit
  -> configured upstream MCP endpoint
```

A deployed gateway beside the listener, or an authenticated tunnel to its host,
could provide the protected route. **Neither is configured by `mcp-listen`.**
Keep the listener on loopback. Changing its bind to `0.0.0.0` does not supply
TLS, caller authentication, or agent identity.

Before selecting and deploying that gateway, specify:

- A reachable hostname and TLS certificate trusted by the hosted client, plus
  the network route from the gateway to the listener.
- Connector authentication supported by the actual client. Define how its
  authenticated identity selects one fixed agent policy; arbitrary callers
  must not enter a listener and be recorded as Mira.
- The boundary between gateway credentials and upstream NockCC credentials.
  Do not assume changing the hostname preserves existing OAuth or bearer-token
  behavior. Keep credentials out of URLs, logs, and audit events.
- Session isolation. The current gate's card state, limits and identity are
  process-scoped. It is not a shared multi-tenant gateway; unrelated agent
  sessions must not share that state.
- Stream/session handling, request limits, timeouts, origin checks and operator
  access controls at the gateway. The local handler accepts POST only; GET
  stream resumption and DELETE session termination are not implemented there.

These are deployment design requirements, not claims that the current binary
already provides them. Local stdio seats can use `proxy` or the `mcp-http`
bridge independently; their setup does not establish hosted-seat coverage.

## Response and failure behavior

Tool calls use the same enforcement gate as stdio. Denied requests return a
JSON-RPC error without contacting upstream. Denied notifications return an
empty HTTP 202. Allowed requests carry canonical JSON upstream.

Tool discovery is filtered in both JSON and SSE responses. Each inspected JSON
body or SSE event is limited to 10 MiB. Pagination, tool metadata, SSE event IDs,
and unrelated messages are retained. Other responses stream through without
this discovery cap. Card-state updates require a matching successful JSON
response; SSE tool results currently do not commit card state.

Proxy or gateway failure must be visible to the connector. Document an operator
rollback to the original upstream endpoint and test it; do not promise a fixed
recovery time. Audit-write failures currently log an error rather than blocking
all tool execution. That behavior needs an explicit operational decision before
claiming every hosted call is durably audited. Do not rely on an untested
tripwire as the hosted listener's recovery mechanism.

## Validation and the Kevin-gated cutover

Local development and stub-upstream tests can proceed without changing Mira's
connection. Local acceptance covers policy denial, input validation, approval,
rate limits, discovery filtering, streaming and signed-trail verification.
`selftest` exercises synthetic enforcement probes; it is not proof of a live
hosted route.

After the gateway design is implemented, a separate test connector must prove
cloud reachability through its HTTPS endpoint, correct authentication and
identity, session/stream behavior, a blocked canary, and a signed audit entry
that verifies. Never use a connector pointed at localhost as that test.

**The live cutover remains Kevin-gated:** only after those checks, re-point
Mira's managed connector from `https://cc.nocktechnologies.io/mcp` to the
validated gateway endpoint. Verify real traffic in the intended agent's audit
trail and Live Wall, and exercise the documented rollback. This document and
the local code fixes do not perform that cutover.
