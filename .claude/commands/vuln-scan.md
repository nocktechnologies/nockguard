Scan the user's NockGuard deployment for security weaknesses. Read the policy file and audit trail, then report findings with severity and concrete fixes.

## Severity levels

- **CRITICAL**: Active misconfiguration that leaves agents unguarded right now.
- **HIGH**: Control gap that a misbehaving or compromised agent could exploit.
- **MEDIUM**: Missing defense-in-depth layer; not an immediate gap but increases risk.
- **LOW**: Best-practice gap; low probability or low impact.

Always report CRITICAL and HIGH first. Do not soften findings.

## Step 1 — Locate and read the policy

```bash
# Default location (`nockguard init` writes it)
cat ~/.nockguard/policy.yaml

# Or ask the user for the path if non-standard
```

If no policy file exists: **CRITICAL — NockGuard has no policy. `nockguard proxy` without a policy starts observe mode: every tool is allowed and nothing is denied (calls are only recorded in a signed audit trail; `cmd/nockguard/observe.go`). Run `nockguard init` to scaffold a default-deny policy, then pass it with `--policy`.**

## Step 2 — Policy structure checks

Read the YAML and flag each of the following:

### 2a. Allow-all agents (CRITICAL)

An agent with no `allow` list and `mode: allow` allows EVERY tool that is not denied (`internal/policy/policy.go`, `Evaluate`). An agent with no `allow` list and `mode` omitted or `deny` is denied every tool, so `my-agent: {}` is not an exposure:

```yaml
# BAD — allow-all
agents:
  my-agent:
    mode: allow
```

Fix: replace it with an explicit allow list, or set `mode: deny`.

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

If the audit trail exists, read it for high-signal events. An agent signed with a per-agent `keygen --agent` key writes `~/.nockguard/logs/<agent>.audit.jsonl` (`policy.AgentAuditPath`); otherwise the trail is the policy-wide `audit.path` (default `~/.nockguard/logs/audit.jsonl`), and `--audit` overrides both. Set `TRAIL` to the one under review; `ls ~/.nockguard/logs/` lists them:

```bash
TRAIL=~/.nockguard/logs/coder.audit.jsonl

# Tail recent events
tail -n 100 "$TRAIL" 2>/dev/null || echo "No audit log found at $TRAIL"

# Block events — always HIGH-signal (injection / secret-exfil attempts)
jq 'select(.decision == "block")' "$TRAIL" 2>/dev/null

# Deny volume by agent and tool
jq -r 'select(.decision == "deny") | "\(.agent) \(.tool)"' "$TRAIL" 2>/dev/null | \
  sort | uniq -c | sort -rn | head -20

# Ratelimit events — potential runaway indicator
jq 'select(.decision == "ratelimit")' "$TRAIL" 2>/dev/null

# Spend-cap hits (recorded as decision ratelimit, reason spend-cap)
jq 'select(.decision == "ratelimit" and .reason == "spend-cap")' "$TRAIL" 2>/dev/null
```

Interpret what you find:

| Pattern | Severity | Meaning |
|---------|----------|---------|
| Any `block` event | HIGH | Input validator caught something — injection attempt, secret exfil, or path traversal. Investigate the agent and the pattern that fired. |
| `would-deny` events | LOW–MEDIUM | A `shadow` allowlist miss: the call was allowed but would be denied once `shadow` becomes `allow`. Review before enforcing. |
| Dense `deny` on destructive tools | Low | Policy working correctly — informational. |
| Dense `deny` on read tools the agent clearly needs | MEDIUM | Policy too tight — agent is being blocked on legitimate calls. May drive the agent to find workarounds. |
| `ratelimit` cluster in a short window | MEDIUM | Agent running hot or looping. |
| Spend-cap hit | LOW–HIGH | Review whether the cap is calibrated or the agent overran it. |

## Step 4 — Verify the audit chain

If signing is configured, verify chain integrity:

```bash
# In a fresh shell, set these to the same trail selected in Step 3 and its signing agent.
: "${TRAIL:?Set TRAIL to the exact trail under review in Step 3}"
: "${AGENT:?Set AGENT to that trail's signing agent}"
# Per-agent key written by `nockguard keygen --agent <name>` (reads ~/.nockguard/keys/<name>.pub)
nockguard verify --agent "$AGENT" --audit "$TRAIL"

# Every per-agent trail in the audit directory
nockguard verify --all

# Ed25519 with an explicit public key, or HMAC
nockguard audit verify --ed25519-pub-env NOCKGUARD_AUDIT_ED25519_PUB --audit "$TRAIL"
nockguard audit verify --key-env NOCKGUARD_AUDIT_KEY --audit "$TRAIL"
```

Exit codes (`runAudit`, `verifyAllAgents` in `cmd/nockguard/main.go`): a trail file that was deleted or cannot be opened exits 2 (`audit.VerifyEd25519` returns the open error, `main.go:988`, reported as TAMPER at `main.go:1004`), and a broken chain exits 2. A missing public key or unset key env var exits 1 (`requirePubHex`, `main.go:977-981`), and `verify --all` exits 1 for an unverifiable key or when it finds no trails (`NO_TRAILS`). Exit 1 reads as a setup issue only when auditing was never configured (no `audit.enabled: true`, no `keygen` keys, no earlier trail). When the policy has auditing enabled, a missing trail or missing public key is **HIGH: possible deletion**, not a setup issue; report it and look for who removed the file. Exit 2 is trail read or integrity failure after key selection; assume tampering. **Exit 2 is a CRITICAL security event.** Do not proceed — escalate immediately and treat the chain as forensic evidence.

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
