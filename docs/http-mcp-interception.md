# HTTP MCP Interception — Phase-0 Design Note (N8761)

> **Superseded for the flagship seat** by
> [`docs/design/n8761-phase0-http-listener-forward-proxy.md`](design/n8761-phase0-http-listener-forward-proxy.md).
> The stdio-bridge transport chosen below (Candidate 1a) is inapplicable to
> Mira's managed remote-HTTP connector, which has no local `.mcp.json` command
> entry to load a stdio server into. The HTTP listener (Candidate 1b, filed here
> as a fallback) is promoted to the chosen path in that note. `nockguard mcp-http`
> as built remains valid for genuinely stdio-wrappable seats.

## Context

Mira's flagship seat reaches NockCC via the **claude.ai remote-HTTP connector**
(`claude mcp list` → "claude.ai NCC: https://cc.nocktechnologies.io/mcp ✔ Connected").
A stdio proxy cannot wrap an HTTP endpoint, which is why the pilot has been dark
since 2026-07-07 (`~/.nockguard/logs/mira.audit.jsonl` frozen at
2026-07-07T05:17Z, no proxy running).

## Interception Point

A **localhost MCP-aware proxy** that Claude Code connects to as its NockCC MCP
server. The proxy forwards every MCP JSON-RPC call to the real remote upstream
(`https://cc.nocktechnologies.io/mcp`) and records a signed audit event per
`tools/call`. No calls are blocked — observe mode only.

## Transport Choice

### Candidate 1a — stdio MCP server (CHOSEN)

Claude Code launches `nockguard mcp-http --upstream <url> --agent mira` over
stdio via the existing `.mcp.json` command mechanism. The proxy speaks the MCP
stdio protocol (newline-delimited JSON-RPC) to Claude Code and bridges each
request to the HTTP upstream via POST. Auth headers/session (`Mcp-Session-Id`)
are preserved transparently.

**Why chosen:** Lowest cutover risk. The `.mcp.json` `command:` entry is the
proven mechanism for stdio MCP servers. No account-level connector URL changes
needed. Uses NockGuard's existing per-agent Ed25519 signing Auditor unchanged.

### Candidate 1b — local HTTP listener (FALLBACK)

The managed connector URL could be re-pointed to `http://localhost:PORT/mcp` if
the account-managed connector allows localhost URLs. Not chosen for Phase 1
because the URL re-pointing path has higher uncertainty (account UI / managed
connector config) compared to the deterministic `.mcp.json` swap.

### Candidate 2 — NCC server-side middleware (REJECTED)

The guard would live INSIDE the product it guards (NockCC). Rejected: weaker
isolation, requires NockCC prod changes, and defeats the purpose of an
independent audit trail for the flagship seat.

### Candidate 3 — bare MCP protocol shim (SUBSUMED)

Essentially what Candidate 1a is, but framed as a NockGuard proxy mode so it
reuses the existing audit, policy, and Wall infrastructure. Not a separate candidate.

## Phase-1 Build

The `nockguard mcp-http` subcommand (see `cmd/nockguard/main.go` and
`internal/proxy/mcphttp/`) implements:

1. **stdio↔HTTP bridge** — reads newline-delimited JSON-RPC from stdin (what
   Claude Code writes), POSTs each to the HTTP upstream, and writes the response
   back to stdout. Handles both `application/json` and `text/event-stream` (SSE)
   upstream responses. Session continuity via `Mcp-Session-Id` header capture.

2. **Per-call audit** — for every `tools/call`, records
   `audit.Event{Agent, Tool, Decision: "observe", Reason: "mcp-http-intercept"}`
   through the existing Ed25519-signing Auditor → `~/.nockguard/logs/mira.audit.jsonl`,
   chain verifying. Auth headers and tool arguments are NEVER logged (only tool
   name + decision).

3. **Observe mode only** — the proxy never blocks or denies a call; every
   request is forwarded unconditionally. This matches `WithEnforce(false)`
   semantics in the egress proxy.

4. **Kill-switch tripwire** — `NOCKGUARD_TRIPWIRE=1` disables audit writes while
   still forwarding calls (never a silent dead-end). The proxy logs loudly on
   every startup when the tripwire is engaged.

## Cutover Plan (Mira executes, not the builder)

1. Generate a per-agent keypair if not present:
   ```bash
   eval $(nockguard keygen --agent mira)
   export NOCKGUARD_AGENT_MIRA_ED25519_KEY="<seed>"
   ```

2. Edit `agents/mira/.mcp.json` — replace the remote-HTTP entry with a `command:`
   stdio entry that launches the proxy:
   ```json
   {
     "mcpServers": {
       "claude.ai NCC": {
         "command": "nockguard",
         "args": ["mcp-http",
                  "--upstream", "https://cc.nocktechnologies.io/mcp",
                  "--agent", "mira",
                  "--auth-env", "NOCKCC_MCP_AUTH"]
       }
     }
   }
   ```

3. Set `NOCKCC_MCP_AUTH` to the Authorization header value if the upstream
   requires one (e.g. `Bearer <token>`).

4. Restart the session and verify:
   - `claude mcp list` shows the server as Connected.
   - Make a test NockCC call.
   - `tail -f ~/.nockguard/logs/mira.audit.jsonl` shows a signed entry.
   - `nockguard verify --agent mira` exits 0.
   - The Live Wall (`nockguard-wall`) renders the entry.

## Revert Plan

To restore the direct connection in under 30 seconds:

```bash
# Option A: engage the tripwire (proxy still runs, audit disabled, logs loudly)
export NOCKGUARD_TRIPWIRE=1

# Option B: revert .mcp.json to the original remote-HTTP connector entry
# (edit back, restart session)
```

Option B is the clean revert; Option A is the zero-downtime fast escape when
you need to rule out the proxy as a problem.

## Acceptance Criteria

- `go test ./...` green, including `internal/proxy/mcphttp/`.
- A simulated tools/call through the proxy: (a) reaches a stub upstream, (b)
  produces a signed audit entry with a verifying chain, (c) is observe-only
  (never blocks), (d) tripwire forwards directly with no audit writes.
- Mira can execute the cutover and verify real traffic lands in
  `mira.audit.jsonl` + the Live Wall with a passing chain.
