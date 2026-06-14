Walk the user through threat-modeling their NockGuard deployment. Guide them from a blank slate to a policy that matches their actual risk surface.

## Your goal

By the end of this session the user should be able to answer:
1. Which agents exist and what MCP servers they connect to.
2. Which tools are high-risk (destructive, exfiltrating, or admin-level).
3. Which tools each agent legitimately needs.
4. What policy controls (allow, deny, validate_input, rate_limit, spend_cap, require_approval) are appropriate for each agent.
5. Whether the audit trail should be enabled and, if so, what signing level is needed.

## Step 1 — Inventory

Ask the user to list:
- Every AI agent that will connect through NockGuard (name, purpose, operator trust level).
- Every MCP server each agent connects to (filesystem, GitHub, database, NockCC, custom).

If they don't know all the tool names yet, run:

```bash
# One-shot: list every tool the upstream server exposes.
# Replace the command with their actual upstream.
nockguard proxy --upstream "npx mcp-server-nockcc" --agent probe 2>&1 | head -20
```

Or ask them to check the MCP server's documentation / README for its tool list.

## Step 2 — Classify tools by risk

For each MCP server, sort its tools into three tiers:

| Tier | Examples | Default posture |
|------|----------|-----------------|
| **Read-only** | `*_list`, `*_get`, `*_read`, `*_search` | Allow freely |
| **Write / mutate** | `*_create`, `*_update`, `*_push`, `*_set` | Allow only where the agent's job requires it |
| **Destructive / admin** | `*_delete`, `*_archive`, `*_kill_switch*`, `*_private_*`, `*_exec` | Deny by default; require approval for any exception |

Ask the user: "Does any of these tools in tier 3 need to be available to any agent? If yes, does it need a human nod before running?"

## Step 3 — Map agents to tools

For each agent, build a minimal allow list:
- Start with zero permissions.
- Add only what the agent needs for its primary job.
- Add deny rules for tier-3 tools that could plausibly be reached via a wildcard (deny wins over allow — use it as a safety net).

Prompt the user: "If this agent were compromised or confused, which tools would do the most damage? Deny those explicitly, even if they don't appear in the allow list."

## Step 4 — Choose input validation

Recommend `validate_input` categories based on what each agent touches:

| Agent touches | Add category |
|--------------|--------------|
| Database queries or SQL-like params | `sqli` |
| File paths, repo paths, working directories | `path_traversal` |
| Any external input that could carry credentials | `secrets` |

Default recommendation: enable all three for any agent that accepts user-supplied text or external data.

## Step 5 — Set rate and spend limits

Ask:
- "How often should this agent call tools in a normal session?" → set `rate_limit`.
- "What is the absolute maximum number of tool calls this agent should make in one session before you want it to stop?" → set `spend_cap`.

Conservative starting values for a typical AI coding agent:
```yaml
rate_limit:
  max_calls: 60
  window: 1m
spend_cap:
  max_calls: 2000
```

## Step 6 — Identify approval gates

Ask: "Are there any tools in the allow list that you want a human to approve each time, even if policy allows them?" These go in `require_approval`.

Good candidates: any `spend_*`, `kill_switch_*`, `archive_*`, `push_*` to production branches, `exec` tools.

Requires the approval bot: set `NOCKGUARD_APPROVAL_BOT_TOKEN` and `NOCKGUARD_APPROVAL_CHAT_ID`.

## Step 7 — Decide on auditing

Ask the user what level of accountability they need:

| Need | Config |
|------|--------|
| Local record for debugging | `audit.enabled: true` (no signing) |
| Tamper-evident trail (e.g., compliance) | Add `sign_key_env: NOCKGUARD_AUDIT_KEY` |
| Non-repudiable trail (court-grade) | Run `nockguard keygen`; use `sign_ed25519_key_env` |
| Real-time visibility across the fleet | Add `forward.enabled: true` pointing at NockCC |

## Step 8 — Produce the policy draft

Synthesize the answers into a concrete `policy.yaml`. Use the starter template as a base:

```bash
nockguard init   # writes ~/.nockguard/policy.yaml if it doesn't exist
```

Then fill in per-agent allow/deny rules from Step 3, validate_input from Step 4, limits from Step 5, require_approval from Step 6, and the audit block from Step 7.

After drafting, run `/policy-lint` to catch structural problems before deploying.

## What NOT to do

- Do not leave any agent with no allow list and no `mode: deny` — that is an implicit allow-all.
- Do not put signing keys or API keys in the policy file. Always use `*_env` references.
- Do not model the policy on what tools you think will be called. Model it on what tools you want to allow if the agent misbehaves.
