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

The fastest path — scaffold a default-deny starter policy, then run the firewall:

```bash
nockguard init                                  # writes ~/.nockguard/policy.yaml (won't clobber an existing one)
nockguard proxy --upstream "npx mcp-server-nockcc" --agent my-agent
```

`init` generates a commented, default-deny policy you edit in place — no hand-writing YAML to get started. Or write one yourself:

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

### Forwarding to the NockCC ops-log

NockGuard can stream **enforcement decisions** (`deny`, `block`, `ratelimit`) to the [NockCC](https://cc.nocktechnologies.io) ops-log, so what the firewall blocks across the fleet shows up in one Command Center feed. Allowed calls and tool-list hides are not forwarded — the centralized feed stays high-signal, while the local JSONL keeps the complete record.

```yaml
audit:
  enabled: true
  forward:
    enabled: true
    url: https://cc.nocktechnologies.io
    api_key_env: NOCKCC_API_KEY   # the key is read from this env var, never stored in the policy file
```

Forwarding is **asynchronous and fail-open**: events post on a background worker, `Enqueue` never blocks (it drops if the buffer saturates), and any HTTP/transport error is swallowed — a slow or unreachable NockCC can never stall or fail a tool call. Severity maps as `block → high` (an injection / secret-exfil attempt) and `deny` / `ratelimit → warn`. Misconfiguration (forwarding enabled with no `url`, or an `api_key_env` that doesn't resolve) fails loud at startup rather than silently dropping every event.

### Tamper-evidence (HMAC hash-chain)

Audit entries can be signed with an HMAC hash-chain — each entry's signature covers its own content plus the previous entry's signature, so any insertion, deletion, or edit anywhere in the trail breaks the chain from that point forward. Signing is opt-in (provide a key); without one, the trail behaves exactly as the unsigned JSONL above. This closes Phase 4.

```bash
nockguard audit verify --key-env NOCKGUARD_AUDIT_KEY   # exit 0 = intact, 2 = tampered
```

### Non-repudiation (Ed25519)

HMAC is *tamper-evident* but symmetric: whoever verifies the trail holds the same key that produced the signatures, and could therefore forge them. **Ed25519** signing closes that gap — it is asymmetric. A private key signs; the trail is verified with the corresponding **public key**, which *cannot* produce signatures. So a passing verification is proof that the holder of the private key signed every entry — the verifier never has the power to forge one. That is the difference between "this trail wasn't edited" and "this trail is *non-repudiable*": court-credible, and aligned with the emerging [IETF agent-audit-trail](https://datatracker.ietf.org) direction (hash-chain + asymmetric signatures).

Generate a keypair, then point the policy at the private seed via an env var:

```bash
nockguard keygen
# NOCKGUARD_AUDIT_ED25519_KEY=<private seed — secret, never commit>
# NOCKGUARD_AUDIT_ED25519_PUB=<public key — share with verifiers>
```

```yaml
audit:
  enabled: true
  sign_ed25519_key_env: NOCKGUARD_AUDIT_ED25519_KEY   # hex 32-byte seed or 64-byte key; read from env, never stored in the policy file
```

`sign_ed25519_key_env` takes precedence over `sign_key_env` when both are set. Verify the trail with only the public key — the signer's secret is never needed to audit it:

```bash
nockguard audit verify --ed25519-pub-env NOCKGUARD_AUDIT_ED25519_PUB   # exit 0 = intact + authentic, 2 = tampered or wrong signer
```

## Live Wall

The audit trail is a file; the **Live Wall** makes it something you watch. `nockguard-wall` tails the audit JSONL and streams each policy decision to a local browser dashboard in real time, color-coded by outcome — every tool call an agent attempted and exactly what the firewall did about it. It is the visible layer over NockGuard's invisible enforcement: visceral proof of the accountability moat.

```bash
go run ./cmd/nockguard-wall                 # serves http://127.0.0.1:8787 (loopback = private)
go run ./cmd/nockguard-wall --demo          # synthesize a sample stream when there's no live traffic
go run ./cmd/nockguard-wall --audit <path>  # point at a specific audit JSONL
```

It binds to loopback by default (private), embeds its own page (single binary, no assets to ship), and replays the existing audit record on open so the wall is populated immediately, then streams new decisions as they land. The wall reads only the recorded decision (agent, tool, outcome, reason) — never raw tool-call parameters, consistent with the audit trail's no-payload rule.

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
- [x] Phase 4: Audit trail — structured JSONL trail, NockCC ops-log forwarding, and tamper-evident HMAC hash-chain signing
- [x] Phase 4+: Non-repudiable audit — Ed25519 asymmetric signing (private-key signs, public-key verifies), `keygen`, standards-aligned
- [x] Phase 5: Interactive approval gates — human-in-the-loop hold on consequential tools (dedicated Telegram bot, fail-safe deny)
- [x] Live Wall: real-time local dashboard streaming every policy decision from the audit trail

## License

MIT
