# Customer-run HTTP MCP gateway contract

Nock Command is a downloadable, self-hosted application. NockGuard can ship
with it or be installed separately for free. Credentials and infrastructure
belong to the customer. This document describes the optional remote HTTP path;
it does not require a public gateway or an OAuth server for local stdio use.

Status: local implementation and validation. One gateway process serves one configured agent and one
OAuth subject/client pair. Tracking: N10745. This extends the N8761 deployment
design. Session gates run in-process; the only network listener is loopback.

## Authentication and routing

The `mcp-gateway --config <path>` command is an OAuth protected resource, not an
authorization server. An operator selects an OAuth server supporting Claude's
authorization-code/PKCE flow and RFC 7662 introspection. Each request is
introspected over HTTPS with a separate environment-backed service credential.
There is no token cache. Authorization requires an active, unexpired token,
the configured issuer, the gateway resource audience, required scope, subject
and OAuth client ID. Missing or malformed claims fail closed. No request field
selects an agent or upstream. Discovery uses RFC 9728 resource metadata.

The introspection profile requires `active: true`, `iss`, `sub`, `client_id`,
`aud` (string or string array), `scope` (space-separated), integer `exp`, and
`token_type: Bearer`; an optional future `nbf` is rejected. Register the OAuth
client before configuring its ID. Unknown clients never acquire the configured
agent identity, including newly registered clients. Introspection authentication
can be `Authorization` (the configured token is prefixed with `Bearer `) or
`X-Agent-Token`. It has a five-second deadline and a 64-KiB response limit.

The upstream receives only a separately provisioned `X-Agent-Token`, never the
connector bearer token. Both outbound destinations must be HTTPS, without URL
credentials, queries or fragments. Redirects are refused. Secrets are named by
environment variable in configuration, never supplied as configuration values.

## Sessions and enforcement

Successful HTTP initialization creates a random gateway session handle; the
upstream session ID stays private. Each session has a fresh enforcement gate
and card state. Policy, rate/spend limits, trust and signed audit writer are
shared for the configured agent, so opening sessions cannot reset a quota.
Every subsequent POST requires that handle and the same authenticated
subject/client pair. Tokens may rotate without changing identity. Unknown or
expired sessions return 404 and require reinitialization. Reinitialization
inside an existing session is rejected.

Sessions are bounded (64, 30-minute idle expiry); at most one POST runs per
session, returning 429 for overlap. Busy sessions are never evicted. A global
64-request limit also bounds authentication work. Requests expire after five
minutes or token expiry, whichever is first. Bodies are capped at 10 MiB;
headers and body reads have deadlines. GET streaming and DELETE termination
remain unsupported (405). POST SSE ends after its matching result. Once upstream
headers arrive, a tool-call SSE result or JSON/SSE discovery response must arrive
within 30 seconds; heartbeats do not extend that deadline. Buffered JSON tool
results have the same 30-second limit. Buffered tool responses must carry a
matching JSON-RPC 2.0 result or error envelope. Invalid envelopes, transport
failures and unreadable, oversized or timed-out responses report that execution
may have occurred and must not be retried automatically.
Origins, when supplied, must be explicitly allowed. The configured public host
must match; forwarded identity/host headers are not trusted.

## Deployment boundary

The command binds explicit loopback only. A co-located HTTPS ingress or tunnel
must preserve the public Host and route `/mcp` and
`/.well-known/oauth-protected-resource/mcp` to it. Existing `mcp-listen` behavior
does not change. No authorization-server implementation, public bind, DNS,
hosting purchase, production credential provisioning, or connector change is
included. NockCC's existing `nockcc-mcp` audience is not a gateway audience;
its current MCP auth also needs scoped Agent-token support before this route
can use NockCC. These are deployment prerequisites, not fallback paths.

The gateway requires durable local auditing at runtime. Before forwarding a
tool call it writes and synchronizes a `dispatch` decision; this proves that
forwarding was authorized, not that the tool executed. Deferred decision rows
are synchronized before a JSON result or matching SSE result is released.
SSE results update card state only on a matching successful JSON-RPC response.
Discovery hide decisions are also recorded before the filtered result leaves.

A write, checkpoint or synchronization failure stops new requests across every
session sharing that auditor. If the failure occurs after forwarding, the
response says the tool **may have executed** and must not be retried
automatically. NockGuard cannot roll back an upstream side effect. In-flight
calls may have run; an operator must inspect their actual upstream state.
Repair storage, verify the signed trail, and restart the gateway to reopen its
writer; repairing the filesystem alone does not clear the failure. A dispatch
entry without the later decision is an unresolved attempt, not proof of success.
Required auditing uses filesystem synchronization; it cannot guarantee against
hardware or filesystems that falsely report durable writes, nor atomically
commit a remote action and a local audit record.

Local acceptance must prove auth failures never reach upstream, credential separation, policy
denial/discovery filtering, session separation, quota sharing, bounded failure
handling and signed audit verification. Validate the customer's selected HTTP
client and server together before switching their endpoint. Rollback restores
the previous endpoint and its authentication setup. The internal Mira pilot in
N8761 is a separate deployment, not a prerequisite for the downloadable product.

## Customer setup

1. Start from [`gateway.example.yaml`](../gateway.example.yaml). Select the
   public resource URL, authorization server, registered client and permitted
   subject. Configure the issuer to mint tokens for that exact resource URL.
2. Provision two distinct service credentials through the host's secret manager:
   introspection and upstream. Configure their environment variable names in
   YAML. Provision the per-agent Ed25519 key using the existing key-management
   workflow. The command requires that key and `audit.enabled: true`; it rejects
   missing credentials or disabled audits at startup. Keep audit/trust data on
   durable storage accessible only to the service account.
3. Supply the selected agent's reviewed policy, including a harmless denied
   canary tool. Run `nockguard selftest --policy <path>` and the integration
   tests. Selftest proves synthetic gate enforcement, not the hosted route.
4. Run `nockguard mcp-gateway --config <path>`. A co-located ingress or tunnel
   exposes the two documented paths over trusted HTTPS, preserving Host. Strip
   secrets from ingress access logs. The HTTP port must stay private. Process
   restart drops sessions; clients must initialize again. For another agent or
   caller identity, deploy a separate process/configuration.
5. Use a separate test connector with that registered client. Prove
   reachability, login, allow/deny behavior, JSON/SSE responses, token renewal,
   and audit verification, including an audit-storage failure; then test rollback.
   Record that evidence before switching the customer's working endpoint.

References: [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization),
[RFC 7662](https://www.rfc-editor.org/rfc/rfc7662), and
[N8761 deployment checks](n8761-phase0-http-listener-forward-proxy.md).
