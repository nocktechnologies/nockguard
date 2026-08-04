# N8761 Phase-0 Design — Local HTTP-Listener Forward Proxy (Option A)

Status: Design-only. No runtime, config, or live-connector changes. The single
step that re-points Mira's live NockCC connection is Kevin-gated (see
[The Kevin-Gated Cutover](#the-kevin-gated-cutover)).

Supersedes, for the flagship seat, the transport choice in
[`docs/http-mcp-interception.md`](../http-mcp-interception.md). That note chose
**Candidate 1a — stdio MCP server** and filed the HTTP listener as
**Candidate 1b (FALLBACK)** on the belief that a `.mcp.json` `command:` swap was
the deterministic path. Ground truth (below) inverts that: the flagship seat has
no local `.mcp.json` command surface to load a stdio server into, so 1a is not
merely riskier — it is **inapplicable** to the flagship seat. This document
promotes the HTTP listener from fallback to the chosen path.

---

## Problem

The dogfood pilot is dark. `~/.nockguard/logs/mira.audit.jsonl` is frozen at
`2026-07-07T05:17Z` with 4 entries and no proxy process is running. Every MCP
call Mira's flagship seat makes to NockCC since that timestamp is unaudited by
NockGuard — the product does not guard its own flagship agent.

Root cause (Nock N8761): Mira's flagship seat reaches NockCC through an
**account-managed `claude.ai` remote-HTTP MCP connector** — a hosted connector
whose endpoint is `https://cc.nocktechnologies.io/mcp`. It is configured in the
account UI, not in a local `.mcp.json`.

PR #48 (commit `bdf88d1`, `feat(n8761): MCP-aware HTTP proxy for flagship seat
dogfood`) shipped `nockguard mcp-http` — a stdio↔HTTP bridge
(`internal/proxy/mcphttp/mcphttp.go`). Claude Code launches it as a **stdio MCP
server via a local `.mcp.json` `command:` entry**; it POSTs each JSON-RPC line
to the HTTP upstream and writes the response back to stdout, recording a signed
audit event per `tools/call`.

The bridge is correct and merged, but it cannot intercept the flagship seat: a
**managed remote-HTTP connector has no `.mcp.json` command entry to point at a
local stdio process**. The one mechanism `mcp-http` depends on does not exist for
the seat that matters. Result: the interception point PR #48 built is
unreachable from the flagship connector, and the pilot stays dark.

---

## Goal

Stand up a **local HTTP forward-proxy** that the managed connector re-points its
NockCC endpoint to. It:

1. Accepts the connector's MCP JSON-RPC request over HTTP on `127.0.0.1`.
2. Intercepts every `tools/call`, running it through NockGuard's existing
   enforcement pipeline — allowlist/policy, input validation, rate-limit + spend
   caps, approval gate — and appends a per-call Ed25519-signed audit event.
3. On allow, forwards the (canonicalized) request to the real NockCC remote-HTTP
   endpoint (`https://cc.nocktechnologies.io/mcp`), preserving the connector's
   own auth token and the `Mcp-Session-Id`, and **streams the response
   (`application/json` or SSE) back** to the connector unchanged.
4. On deny/block/rate-limit/approval-denied, returns a JSON-RPC error as the HTTP
   response body — never reaching upstream.

This is the same enforcement the stdio proxy already applies, moved behind an
HTTP listener the managed connector can actually target.

---

## Why Option A over Option B

The arc forks on one Kevin-gated product decision:

- **Option A — HTTP-listener forward-proxy (this design).** The managed connector
  re-points its NockCC endpoint URL to the local proxy. Scales to **all 46 fleet
  seats** — every seat that reaches an MCP endpoint over remote HTTP is covered
  by re-pointing its endpoint, no per-seat wrapper. It is also the **only path
  that exercises remote-HTTP MCP interception** — the exact surface real
  NockGuard customers will need, since managed remote-HTTP connectors are how
  hosted agents actually attach to MCP servers.

- **Option B — pivot to a stdio-MCP seat.** Only **1 of 46 fleet seats** is
  stdio-wrappable, so `mcp-http` (PR #48) can guard exactly that one seat and no
  more. B never touches the remote-HTTP path customers use. It is a **1/46
  near-dead-end**: it demonstrates the audit trail on a non-flagship seat and
  stops there.

**Decision: Option A.** A covers the flagship seat plus the other 45, exercises
the customer-relevant remote-HTTP interception, and — importantly — **does not
waste PR #48**. A subsumes B's working guts: `post()`'s Accept /
`Content-Type` / `Mcp-Session-Id` handling, `writeSSEResponse`, the shared
1 MB/10 MB scanner buffers, and the `tools/call` name extraction all lift
directly from `internal/proxy/mcphttp/` into A's upstream forwarder. A is B plus
the seat coverage and the real interception surface.

---

## Architecture

Option A is an assembly of three pieces already in the tree, not a new subsystem:

| Component | Reused from | Role |
|-----------|-------------|------|
| HTTP listener + graceful shutdown | `internal/proxy/forwardhttp` (`Run`, `http.Server`, `removeHopByHopHeaders`) | Accept the connector's POST, own the server lifecycle |
| Request interceptor / policy engine | `internal/proxy/stdio.go` (`agentToUpstream` gate) | Canonicalize → policy → validate → rate-limit → approval, on the MCP **tool name** |
| Upstream forwarder + streaming passthrough | `internal/proxy/mcphttp` (`post`, `writeSSEResponse`, session capture, scanner buffers) | POST to the real NockCC endpoint; stream `application/json` or SSE back |
| Audit appender | `internal/audit` (`Auditor.Record`) | Per-call Ed25519-signed entry to `mira.audit.jsonl` |
| Ops-log forwarder / trust | `internal/forward`, `internal/trust` | Surface enforcement events to NockCC; accumulate trust |
| Live Wall | `cmd/nockguard-wall` | Renders the audit trail; unchanged — it reads the same jsonl |

Nothing in that table is rebuilt. The **only new code** is the glue: an
`http.Handler` that reads the request body as a JSON-RPC line, drives it through
the existing gate, and on allow hands it to the existing forwarder.

### What is explicitly NOT inherited from `forwardhttp`

`forwardhttp` is an **egress** proxy: it gates on destination **host**
(`engine.Evaluate(agent, host)`, audits `Tool: "egress:"+host`) and carries the
SSRF guard / CONNECT tunnelling for arbitrary outbound traffic. The MCP proxy
gates on **MCP tool name** — `canonicalToolCall(msg.Params)` →
`engine.Evaluate(agent, toolName)` → `audit{Tool: toolName}` — so its audit rows
are identical in shape to the stdio proxy's and `nockguard verify` / the Live
Wall stay consistent across both proxy modes. We reuse forwardhttp's server
skeleton (`Run`, shutdown, hop-by-hop header stripping) and **not** its egress
policy semantics. The upstream URL is a single operator-configured endpoint, so
CONNECT tunnelling and the arbitrary-host SSRF surface do not apply here.

### Request flow

```
  managed claude.ai connector
  (endpoint re-pointed to  http://127.0.0.1:PORT/mcp )
            │  POST /mcp   { JSON-RPC: tools/call, name:"nock_write", ... }
            │  Authorization: Bearer <connector's own NockCC token>
            ▼
  ┌───────────────────────────────────────────────────────────────┐
  │  NockGuard HTTP listener  (127.0.0.1 only)                     │
  │  [forwardhttp.Run / http.Server skeleton]                     │
  │                                                               │
  │   1. read body → jsonrpc.Decode → canonicalize (dup-key       │
  │      collapse, same as stdio.go)                              │
  │                                                               │
  │   2. tools/call?  ── no ──►  forward verbatim (initialize,    │
  │      │                       tools/list, notifications)       │
  │      yes                                                       │
  │      ▼                                                         │
  │   ┌── ENFORCEMENT GATE  (reused from stdio.go) ───────────┐   │
  │   │  policy.Engine.Evaluate(agent, toolName)              │   │
  │   │     Deny        ──► JSON-RPC error, STOP              │   │
  │   │  require_approval → promote to Ask (N8328)            │   │
  │   │  validate.Validator.CheckParams(canonicalParams)     │   │
  │   │     hit         ──► JSON-RPC error, STOP              │   │
  │   │  ratelimit.Limiter.Allow()  (rate + spend cap)       │   │
  │   │     over        ──► JSON-RPC error, STOP              │   │
  │   │  approval.Approver.Ask(...)  (Ask verdict)           │   │
  │   │     denied/no-approver ──► JSON-RPC error, STOP       │   │
  │   │     (fail-CLOSED, per N8328)                          │   │
  │   └───────────────────────────────────────────────────────┘   │
  │      │ allowed                                                 │
  │      ▼                                                         │
  │   3. audit.Auditor.Record{Agent, Tool:toolName,               │
  │        Decision:"allow"|"deny"|..., Reason} → mira.audit.jsonl │
  │      + forward.Forwarder.Enqueue(enforcement events)          │
  │                                                               │
  │   4. UPSTREAM FORWARDER  [mcphttp.post]                        │
  │      POST canonical body → https://cc.nocktechnologies.io/mcp │
  │      pass inbound Authorization THROUGH unchanged             │
  │      set Accept: application/json, text/event-stream          │
  │      carry Mcp-Session-Id (capture from initialize response)  │
  └───────────────────────────────────────────────────────────────┘
            │  upstream response (json  |  text/event-stream)
            ▼
   5. STREAM back to connector  [mcphttp.writeSSEResponse / json path]
      SSE: relay each `data:` event as it arrives (1MB/10MB buffers)
      json: relay body as-is
            │
            ▼
  managed claude.ai connector  ◄── response, indistinguishable from direct NCC
```

`tools/list` filtering (hide denied tools from the agent) reuses
`filterToolListResponse` from `stdio.go`, and gets **simpler** here: HTTP pairs
each request with its response in one exchange, so the `pending *sync.Map`
request-id bookkeeping the stdio duplex needs is unnecessary — filter the
response inline before streaming it back.

---

## Effort Estimate (phased)

| Phase | Scope | Rough sizing |
|-------|-------|--------------|
| **Phase 0 — Design** (this doc) | Ground the design in the real code; get the Option-A fork ruled by Kevin | Done on merge of this PR |
| **Phase 1 — Listener + forwarder skeleton** | New `internal/proxy/mcplisten` (or extend `mcphttp`): `http.Server` on `127.0.0.1`, decode body, forward to upstream, stream json+SSE back, `Mcp-Session-Id` capture, inbound-auth passthrough. **Observe-only, no policy in path.** Wire a `nockguard mcp-listen --listen 127.0.0.1:PORT --upstream <url> --agent mira` subcommand. e2e test against a stub upstream (reuse mcphttp's e2e harness). **Exit criterion: a throwaway second connector pointed at localhost completes a real NockCC round-trip.** | Small–medium (~1 focused build; most transport code lifts from `mcphttp`) |
| **Phase 2 — Policy-in-path + audit** | Drop the `stdio.go` enforcement gate into the handler: canonicalize, policy Evaluate on tool name, validate, rate-limit, approval, Ed25519 audit append, ops-log forward, `tools/list` filtering. Deny paths return JSON-RPC errors. Full e2e: deny / block / rate-limit / approval / observe, signed chain verifies, tripwire bypasses enforcement. | Medium (mostly wiring existing modules; the gate logic already exists and is tested) |
| **Phase 3 — Dogfood cutover** | Kevin-gated. Re-point the live managed connector to the local proxy; verify real traffic lands in `mira.audit.jsonl` + the Live Wall with a passing chain; `nockguard verify --agent mira` exits 0. | Small execution, **blocked on Kevin's gate** |

Phases 0–2 are fully buildable and testable against a stub upstream **without any
approval and without touching Mira's live connection.** Only Phase 3 rewires the
live seat.

---

## The Kevin-Gated Cutover

Exactly **one** step requires Kevin's approval, because it rewires Mira's live
NockCC connection:

> **Re-point the account-managed `claude.ai` NCC connector's endpoint** from
> `https://cc.nocktechnologies.io/mcp` to the local proxy
> (`http://127.0.0.1:PORT/mcp`, or `https://127.0.0.1:PORT/mcp` if the connector
> requires TLS — see risks).

Everything up to that step is unapproved-buildable:

- Phase 1 + Phase 2 code, tests, and the `nockguard mcp-listen` subcommand.
- Local end-to-end validation against a **stub** upstream.
- A **throwaway second connector** pointed at localhost to prove the managed
  connector accepts a localhost endpoint at all — this probes the one unknown
  without disturbing the live NCC connector, keeping the Kevin gate genuinely
  single.

The gate is the re-point of the live connector, and nothing else. This mirrors
the discipline already stated in the PR #48 merge note: "the cutover that
re-points the flagship MCP connection is a separate, explicitly-approved step."

---

## Open Questions & Risks

1. **Does the managed connector accept a localhost endpoint at all?** This is the
   single fact nobody in this repo can verify from code — it depends on the
   account-managed connector UI's URL validation. **Do not assume `http://
   localhost` is accepted.** Make it the Phase-1 exit criterion, probed with a
   throwaway second connector (above), never by re-pointing the live one.

2. **TLS / cert handling for the re-pointed endpoint.** If the managed connector
   requires `https://`, the local proxy needs a TLS listener with a cert the
   connector's client trusts (a locally-trusted self-signed cert, or a
   `mkcert`-style local CA). Open: whether the connector does strict cert
   validation on a loopback host, and whether a plain `http://127.0.0.1` is
   accepted (many clients special-case loopback). Resolve during Phase 1 with the
   throwaway connector before writing any TLS code.

3. **Auth passthrough — direction reverses vs PR #48.** In `mcphttp` the proxy
   *injects* `Authorization` from `--auth-env`. Here the **managed connector
   already holds its own NockCC token** and sends it to what it believes is
   NockCC. The proxy must **forward the inbound `Authorization` header upstream
   unchanged**, must **never log it** (audit records tool name + decision only,
   never headers or arguments), and must **bind `127.0.0.1` explicitly (not
   `0.0.0.0`)** — a loopback listener now receives a live bearer token, and any
   local process that could reach a wildcard bind could harvest it.

4. **Streaming correctness.** NockCC responses may be `application/json` or SSE.
   The forwarder must relay SSE events as they arrive (not buffer the whole
   stream) and must carry the 1 MB/10 MB scanner buffers from `mcphttp` — the
   PR #48 remediation fixed exactly the silent-drop bug (bufio default 64 KB
   `ErrTooLong`) that a large `nock_list` / identity-doc result triggers. Enforce
   only on the **request**; the response is a passthrough, so enforcement adds no
   response-path latency or correctness risk.

5. **Failure mode — fail-open vs fail-closed.**
   - **Process death is fail-closed by construction:** if the proxy is down, the
     connector's localhost endpoint refuses connections and NockCC calls fail
     *visibly*. That is the desired default and needs no special handling — but it
     means the proxy is now on the critical path for the flagship seat, so it
     needs a fast, documented bypass (re-point the connector back to
     `https://cc.nocktechnologies.io/mcp`, ~30s) as the escape hatch.
   - **In-path decisions are the real design choice, and the existing code is
     inconsistent.** `StdioProxy.audit()` fails **open** on an audit-write error
     (logs `AUDIT-ERROR`, forwards anyway); `approveAsk` with no approver fails
     **closed** (N8328); undecodable/batch input fails **closed**. Recommendation:
     inherit those semantics for parity with the stdio proxy — **but flag
     audit-write failure as an open question.** For a dogfood whose entire purpose
     is the audit trail, silently forwarding an *unaudited* flagship call may be
     unacceptable; consider fail-closed on audit-write failure for the flagship
     agent specifically. Decide before Phase 2.

6. **Tripwire — same name, larger blast radius.** Reuse `NOCKGUARD_TRIPWIRE` and
   its loud-log-on-every-startup contract. **State the changed semantics:** in
   PR #48 the tripwire bypasses **audit only** (calls still forward, unaudited).
   In Option A the proxy is now *in the enforcement path*, so the tripwire must
   bypass **enforcement too** — degrade to pure passthrough (forward every call,
   no deny, no audit) so the operator can rule the proxy out as a problem without
   editing the connector. Same env var, wider effect; document it loudly.

---

## Acceptance Criteria (for the eventual build, not this doc)

- `go test ./...` green, including the new listener package.
- A simulated `tools/call` through the HTTP proxy: (a) reaches a stub upstream,
  (b) is denied / blocked / rate-limited / approval-gated exactly as the stdio
  proxy would, (c) produces a signed audit entry whose chain verifies, (d) has
  its SSE/json response streamed back intact, (e) tripwire degrades to pure
  passthrough with no audit and no enforcement.
- The throwaway-connector probe confirms the managed connector accepts a
  localhost endpoint (Phase-1 exit).
- Post-cutover (Kevin-gated): real flagship traffic lands in `mira.audit.jsonl`
  and the Live Wall with a passing chain; `nockguard verify --agent mira`
  exits 0; `mira.audit.jsonl` advances past its `2026-07-07` freeze.
