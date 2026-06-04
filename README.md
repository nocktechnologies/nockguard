# NockGuard

MCP firewall for AI agent fleets. Guard your agent's tools.

NockGuard is an MCP proxy that sits between AI agents and their MCP servers. Every tool call passes through NockGuard's policy engine before reaching the server. If the call violates policy, NockGuard blocks it and returns an error to the agent.

```
Agent (Claude Code, Codex, Cursor, etc.)
    |
    v
NockGuard (MCP Proxy)
    | <- Policy check: allowlist, deny, wildcard match
    v
MCP Server (NockCC, GitHub, filesystem, etc.)
```

## Install

```bash
brew install nocktechnologies/tap/nockguard
```

Or build from source:

```bash
go install github.com/nocktechnologies/nockguard/cmd/nockguard@latest
```

## Quick Start

1. Create a policy file:

```yaml
# policy.yaml
agents:
  kit:
    allow:
      - "nockcc_nock_*"
      - "nockcc_pipeline_*"
      - "github_*"
    deny:
      - "nockcc_kill_switch_set"

  beck:
    allow:
      - "nockcc_nock_*"
      - "nockcc_ops_log_*"
    deny:
      - "nockcc_spend_*"

  default:
    mode: allow
    deny:
      - "nockcc_kill_switch_set"
      - "nockcc_private_*"
```

2. Run NockGuard as a proxy:

```bash
nockguard proxy \
  --upstream "npx mcp-server-nockcc" \
  --agent kit \
  --policy policy.yaml
```

3. Point your agent at NockGuard instead of the MCP server:

```json
{
  "mcpServers": {
    "nockcc": {
      "command": "nockguard",
      "args": ["proxy", "--upstream", "npx mcp-server-nockcc", "--agent", "kit", "--policy", "policy.yaml"]
    }
  }
}
```

## Policy Rules

- **allow**: Tool patterns the agent can use. Supports `*` wildcards.
- **deny**: Tool patterns blocked regardless of allow rules. Deny takes precedence.
- **mode**: `allow` (default) permits unlisted tools, `deny` blocks them.
- **default**: Fallback policy for agents not listed by name.
- **validate_input** (Phase 2): built-in input-validation categories applied to tool-call arguments — `sqli`, `path_traversal`, `secrets`. Opt-in per agent.
- **block_params** (Phase 2): custom regex patterns; a tool call is blocked if any argument matches.
- **rate_limit** (Phase 3): at most `max_calls` tool calls within a sliding `window` (a Go duration — `30s`, `1m`, `1h`). The allowance refills as the window slides — this bounds bursts and runaway tool-call loops without blocking normal traffic.
- **spend_cap** (Phase 3): a hard cumulative ceiling of `max_calls` tool calls for the whole proxy session. It never refills — once hit, every further call is blocked. This is the kill-before-runaway stop that bounds total cost for an agent left running unattended.

```yaml
agents:
  kit:
    allow: ["read_*", "search_*"]
    validate_input: ["sqli", "path_traversal", "secrets"]
    block_params:
      - "(?i)rm\\s+-rf\\s+/"
    rate_limit:
      max_calls: 60
      window: 1m
    spend_cap:
      max_calls: 5000
```

Rate limiting and spend caps are opt-in and independent — set one, both, or neither. NockGuard sits at the MCP layer and sees tool *calls*, not upstream API token spend, so the spend cap is denominated in tool calls (a proxy for cost), enforced before the call reaches the server. When a call clears the allowlist and input validation but exceeds a limit, the agent receives a JSON-RPC error (`rate limit exceeded` / `spend cap exceeded`); denied or input-blocked calls never consume budget.

## Audit Trail (Phase 4)

NockGuard can write a structured, append-only record of every policy decision — turning the firewall from a gate into an accountable trail of what each agent attempted and what the policy did about it. Enable it with a top-level `audit` block:

```yaml
audit:
  enabled: true
  path: ~/.nockguard/logs/audit.jsonl   # optional; this is the default
agents:
  kit:
    allow: ["nockcc_nock_*"]
```

Each decision is one JSON object per line (JSON Lines):

```json
{"ts":"2026-06-03T18:30:00Z","agent":"kit","tool":"nockcc_kill_switch_set","decision":"deny","reason":"policy"}
{"ts":"2026-06-03T18:30:01Z","agent":"kit","tool":"nockcc_nock_list","decision":"allow"}
```

`decision` is one of `allow`, `deny`, `block` (input validation), `ratelimit`, or `hide` (filtered from `tools/list`). Auditing is opt-in (absent or `enabled: false` keeps Phase 1–3 behavior) and fail-open — an audit write error is logged but never blocks or fails a tool call.

**By design, NockGuard does not write raw tool-call parameters to the audit trail.** Logging arguments would persist exactly the secrets and injection payloads that Phase 2 exists to keep out, so the trail records the *decision* (agent, tool, outcome, reason), not the payload.

Forwarding the trail to the NockCC ops-log for centralized fleet monitoring and optional HMAC signing of entries are the next increments.

## How It Works

NockGuard intercepts two MCP methods:

- **tools/list**: Filters the tool list response, hiding denied tools from the agent.
- **tools/call**: Checks the tool name against policy before forwarding. With Phase 2 validation enabled, it also scans the call's arguments (recursively, keys and values) against the configured rule categories and custom patterns, blocking injection attempts and outbound sensitive-data leaks. With Phase 3 limits enabled, a call that clears policy and validation is then metered against the agent's rate limit and spend cap. Denied, blocked, or over-limit calls get a JSON-RPC error response.

All other MCP traffic passes through unmodified. NockGuard is version-transparent — it works with any MCP protocol version. Input validation is opt-in: an allowlist-only policy behaves exactly as in Phase 1.

## Relationship to NockLock

- **NockLock** = secret isolation ("Fence your environment")
- **NockGuard** = MCP firewall ("Guard your agent's tools")

Same brand, same tap, independent products. Use one or both.

## Roadmap

- [x] Phase 1: Tool allowlists (per-agent, wildcard, default-deny)
- [x] Phase 2: Input validation (SQLi / path-traversal / secrets rule sets + custom regex on tool-call arguments)
- [x] Phase 3: Rate limiting and spend caps (per-agent sliding-window rate limit + hard cumulative session cap)
- [~] Phase 4: Audit trail — structured JSONL trail of every decision shipped; NockCC ops-log forwarding + optional HMAC signing next

## License

MIT
