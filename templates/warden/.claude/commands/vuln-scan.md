Scan the user's NockGuard deployment for security weaknesses. Read the policy file and audit trail, then report findings with severity and concrete fixes.

## Severity levels

- **CRITICAL**: Active misconfiguration that leaves agents unguarded right now.
- **HIGH**: Control gap that a misbehaving or compromised agent could exploit.
- **MEDIUM**: Missing defense-in-depth layer; not an immediate gap but increases risk.
- **LOW**: Best-practice gap; low probability or low impact.

Always report CRITICAL and HIGH first. Do not soften findings.

## Step 1 — Locate and read the policy

```bash
# Default location
cat ~/.nockguard/policy.yaml

# Or ask the user for the path if non-standard
```

If no policy file exists: **CRITICAL — NockGuard has no policy. All tool calls are denied (fail-closed), but there is nothing to review. Run `nockguard init` to scaffold one.**

## Step 2 — Policy structure checks

Read the YAML and flag each of the following:

### 2a. Implicit allow-all agents (CRITICAL)

An agent with no `allow` list AND no `mode: deny` allows EVERY tool:

```yaml
# BAD — implicit allow-all
agents:
  my-agent: {}
```

Fix: add an explicit allow list or set `mode: deny`.

### 2b. Missing default agent (HIGH)

If no `default` entry exists, unrecognized `--agent` values fail-closed (denied), but this also means any agent name typo silently blocks all tools with no warning at the right level. Check:

```bash
grep -A2 "default:" ~/.nockguard/policy.yaml || echo "No default agent policy"
```

Best practice: always include a `default: { mode: deny }` as a backstop.

### 2c. Overly broad wildcards (HIGH)

A single `"*"` in the allow list is an allow-all. Flag it:

```bash
grep -n '"*"' ~/.nockguard/policy.yaml
grep -n "- '\*'" ~/.nockguard/policy.yaml
grep -n "- \*$" ~/.nockguard/policy.yaml
```

Also flag `"*_*"` (matches everything with an underscore) as HIGH — nearly every MCP tool name contains an underscore.

### 2d. Missing input validation (MEDIUM)

An agent that accepts external input without `validate_input` is missing injection defense:

```bash
grep -A20 "agents:" ~/.nockguard/policy.yaml | grep -c "validate_input" || echo "0 agents have validate_input"
```

For each agent without `validate_input`, assess whether it touches file paths, database params, or user-supplied text. If yes, flag as HIGH; if no external input, MEDIUM.

Recommended baseline: `validate_input: [sqli, path_traversal, secrets]`.

### 2e. Missing rate limits (MEDIUM)

No `rate_limit` means a runaway loop can call tools indefinitely:

```bash
grep -c "rate_limit" ~/.nockguard/policy.yaml || echo "No rate limits configured"
```

If an agent has no `rate_limit`, flag MEDIUM. If it also has no `spend_cap`, flag HIGH — there is no runaway kill.

### 2f. Missing spend caps (MEDIUM)

Spend caps are the session-level kill-before-runaway control:

```bash
grep -c "spend_cap" ~/.nockguard/policy.yaml || echo "No spend caps configured"
```

An agent running without either a rate limit or a spend cap can issue unlimited tool calls.

### 2g. No audit trail (MEDIUM)

Without `audit.enabled: true`, there is no record of what agents attempted:

```bash
grep -A5 "^audit:" ~/.nockguard/policy.yaml || echo "No audit block"
```

Flag MEDIUM. Without the trail, the vuln scan has no evidence to work from.

### 2h. Unsigned audit trail (LOW)

An unsigned trail can be edited without detection:

```bash
grep "sign_key_env\|sign_ed25519_key_env" ~/.nockguard/policy.yaml || echo "Audit is unsigned"
```

Flag LOW if `audit.enabled: true` but no signing is configured. For compliance contexts, flag HIGH.

## Step 3 — Audit trail analysis

If the audit trail exists, read it for high-signal events:

```bash
# Tail recent events
tail -n 100 ~/.nockguard/logs/audit.jsonl 2>/dev/null || echo "No audit log found at default path"

# Block events — always HIGH-signal (injection / secret-exfil attempts)
cat ~/.nockguard/logs/audit.jsonl 2>/dev/null | jq 'select(.decision == "block")' 2>/dev/null

# Deny volume by agent and tool
cat ~/.nockguard/logs/audit.jsonl 2>/dev/null | \
  jq -r 'select(.decision == "deny") | "\(.agent) \(.tool)"' 2>/dev/null | \
  sort | uniq -c | sort -rn | head -20

# Ratelimit events — potential runaway indicator
cat ~/.nockguard/logs/audit.jsonl 2>/dev/null | jq 'select(.decision == "ratelimit")' 2>/dev/null

# Spend-cap hits
cat ~/.nockguard/logs/audit.jsonl 2>/dev/null | jq 'select(.reason | test("spend cap"))' 2>/dev/null
```

Interpret what you find:

| Pattern | Severity | Meaning |
|---------|----------|---------|
| Any `block` event | HIGH | Input validator caught something — injection attempt, secret exfil, or path traversal. Investigate the agent and the pattern that fired. |
| Dense `deny` on destructive tools | Low | Policy working correctly — informational. |
| Dense `deny` on read tools the agent clearly needs | MEDIUM | Policy too tight — agent is being blocked on legitimate calls. May drive the agent to find workarounds. |
| `ratelimit` cluster in a short window | MEDIUM | Agent running hot or looping. |
| Spend-cap hit | LOW–HIGH | Review whether the cap is calibrated or the agent overran it. |

## Step 4 — Verify the audit chain

If signing is configured, verify chain integrity:

```bash
# Ed25519
nockguard audit verify --ed25519-pub-env NOCKGUARD_AUDIT_ED25519_PUB

# HMAC
nockguard audit verify --key-env NOCKGUARD_AUDIT_KEY
```

Exit 2 = tampering detected. **This is a CRITICAL security event.** Do not proceed — escalate immediately and treat the chain as forensic evidence.

## Step 5 — Report

Summarize findings as a numbered list, most-severe first. For each finding:

```
[SEVERITY] Short title
What was found: ...
Why it matters: ...
Fix: <exact YAML diff or command>
```

After the list, give a risk score (count of CRITICAL + HIGH findings) and a recommended next step.

Do not omit findings to avoid discomfort. A fleet that doesn't know its agents are exposed is not a secure fleet.
