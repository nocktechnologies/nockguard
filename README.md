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

```yaml
agents:
  kit:
    allow: ["read_*", "search_*"]
    validate_input: ["sqli", "path_traversal", "secrets"]
    block_params:
      - "(?i)rm\\s+-rf\\s+/"
```

## How It Works

NockGuard intercepts two MCP methods:

- **tools/list**: Filters the tool list response, hiding denied tools from the agent.
- **tools/call**: Checks the tool name against policy before forwarding. With Phase 2 validation enabled, it also scans the call's arguments (recursively, keys and values) against the configured rule categories and custom patterns, blocking injection attempts and outbound sensitive-data leaks. Denied or blocked calls get a JSON-RPC error response.

All other MCP traffic passes through unmodified. NockGuard is version-transparent — it works with any MCP protocol version. Input validation is opt-in: an allowlist-only policy behaves exactly as in Phase 1.

## Relationship to NockLock

- **NockLock** = secret isolation ("Fence your environment")
- **NockGuard** = MCP firewall ("Guard your agent's tools")

Same brand, same tap, independent products. Use one or both.

## Roadmap

- [x] Phase 1: Tool allowlists (per-agent, wildcard, default-deny)
- [x] Phase 2: Input validation (SQLi / path-traversal / secrets rule sets + custom regex on tool-call arguments)
- [ ] Phase 3: Rate limiting and spend caps
- [ ] Phase 4: Audit trail with NockCC integration

## License

MIT
