# Observe-only HTTP-MCP reverse proxy (N8761, Phase-1)

NockGuard's original firewall is a **stdio** proxy: it wraps an MCP server that
speaks over stdin/stdout and inspects the JSON-RPC that crosses it. That works
when the agent runtime *spawns* the MCP server as a subprocess.

The flagship dogfood does not work that way. Mira's live seat reaches the NockCC
MCP over **remote HTTP** — `https://cc.nocktechnologies.io/mcp`, via the
claude.ai connector. The connector points at a URL and speaks HTTP; it never
spawns a stdio subprocess. So the stdio proxy can never sit in that path, and the
flagship seat runs unaudited.

**Phase-1 (this):** a localhost, MCP-aware **HTTP reverse proxy** the seat's MCP
URL re-points to. It terminates the MCP-over-HTTP transport, parses the JSON-RPC
tool calls, records a signed audit event, then forwards upstream to the real
endpoint and streams the response back untouched.

## What it is (and is not)

- **Observe-only. It never blocks a call.** Policy is evaluated purely to record
  what enforcement *would* do (`allow` / would-`deny`), exactly like the egress
  forward-proxy's observe mode. Enforcement is deliberately not wired in Phase-1.
- **It audits; it does not re-authenticate.** The seat's `Authorization`/bearer
  header is forwarded upstream unchanged.
- It is **not** the host-level egress proxy (`internal/proxy/forwardhttp`). That
  proxy sees only the *host* over an HTTPS `CONNECT` tunnel; it cannot see MCP
  tool calls. This proxy terminates the MCP HTTP connection itself and sees the
  JSON-RPC.

## Run it

```
nockguard proxy --http \
  --upstream https://cc.nocktechnologies.io/mcp \
  --listen 127.0.0.1:8930 \
  --agent mira \
  --policy ~/.nockguard/policy.yaml
```

Then point the seat's MCP URL at `http://127.0.0.1:8930/mcp`. The local path is
irrelevant — every request is forwarded to the fixed `--upstream` URL.

Audit signing reuses the existing per-agent Ed25519 flow: set the agent's
private seed in the env (`NOCKGUARD_AGENT_MIRA_ED25519_KEY`, from
`nockguard keygen --agent mira`) and the trail is written to
`<audit-dir>/mira.audit.jsonl`, verifiable with only the public key via
`nockguard verify --agent mira`.

## Transport coverage (MCP Streamable-HTTP)

| Path | Status |
| --- | --- |
| `POST /mcp` with a JSON-RPC **object** | Done — parsed for `tools/call`, audited, forwarded. |
| `POST /mcp` with a JSON-RPC **batch array** | Done — each element parsed; every `tools/call` audited. |
| `application/json` response | Done — returned to the client. |
| `text/event-stream` (SSE) response | Done — streamed back **verbatim with per-chunk flushing**, not buffered. The proxy does not need to parse the SSE response (audit happens on the request), so it relays bytes live. |
| `Mcp-Session-Id` handshake | Done — the header is passed through unchanged in both directions, so the upstream session is preserved. |
| Server-initiated stream (long-lived `GET`) | Forwarded transparently (streamed, flushed). Not audited (carries server→client messages, not agent `tools/call`). |
| Session teardown (`DELETE`) | Forwarded transparently. |

### Documented limitations / TODO (Phase-2 candidates)

- **No request/response correlation.** Audit fires when the `tools/call` request
  is seen. The proxy does not wait for, or record, the tool *result* (success vs.
  error) — the response is streamed straight through. Recording outcome would
  require buffering/parsing the (possibly SSE) response.
- **No policy on non-`tools/call` methods.** `resources/*`, `prompts/*`, etc. are
  forwarded without an audit line. Only `tools/call` is recorded in Phase-1.
- **Upstream is operator-fixed at startup.** It is not request-derived, so SSRF
  risk is low; nonetheless the upstream client dials through forwardhttp's
  SSRF-guarded dialer (`forwardhttp.GuardedDial`) as defense-in-depth.

## Kill-switch / tripwire

Set `NOCKGUARD_TRIPWIRE` to any non-empty value to disable auditing and forward
directly. The bypass is **loud**: it logs on startup so a disabled guard is never
silent. Enforcement is never engaged regardless of the tripwire — this is an
observe-only build. To restore monitoring, unset it and restart. To remove the
proxy from the path entirely, point the seat's MCP URL back at the direct
endpoint.

## Reused internals

- `internal/policy` — the policy engine (`Engine.Evaluate`), for the observe
  decision. Not reimplemented.
- `internal/audit` — signed, per-agent Ed25519 hash-chained audit trail. Not
  reimplemented.
- `internal/jsonrpc` — JSON-RPC message parsing.
- `internal/proxy/forwardhttp` — `GuardedDial` (SSRF-guarded dialer) and the
  `http.Server` graceful-shutdown shape.
