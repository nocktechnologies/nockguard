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
set -o pipefail   # a failing jq or tail on the left of a pipe fails the whole pipeline
TRAIL=~/.nockguard/logs/coder.audit.jsonl

# A missing trail is classified in Step 4; a tail or jq failure below is an error, not a clean result.
# Tail recent events
tail -n 100 "$TRAIL"

# Block events — always HIGH-signal (injection / secret-exfil attempts)
jq 'select(.decision == "block")' "$TRAIL"

# Deny volume by agent and tool
jq -r 'select(.decision == "deny") | "\(.agent) \(.tool)"' "$TRAIL" | \
  sort | uniq -c | sort -rn | head -20

# Ratelimit events — potential runaway indicator
jq 'select(.decision == "ratelimit")' "$TRAIL"

# Spend-cap hits (recorded as decision ratelimit, reason spend-cap)
jq 'select(.decision == "ratelimit" and .reason == "spend-cap")' "$TRAIL"
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

Pick the verifier from the policy's signing settings. Do not run the verifiers in turn: a verifier for the wrong scheme can exit 2 and read as tampering. The snippet reads the settings, classifies a missing trail before it calls any verifier, then maps the verifier's own exit status. Run it as its own bash invocation, because it `exit`s and sets `set -e`. Set `TRAIL` to the trail selected in Step 3 and `AGENT` to its signing agent; set `PER_AGENT=1` or `0` when `--audit` gave the trail a name that does not follow `<agent>.<audit.path basename>` (1: signed with the agent's own key; 0: signed with the policy key), and `PUB_ENV` if the Ed25519 public key is not in `NOCKGUARD_AUDIT_ED25519_PUB`:

```bash
set -e
: "${TRAIL:?Set TRAIL to the exact trail under review in Step 3}"
: "${AGENT:?Set AGENT to the signing agent of that trail}"
POLICY="${POLICY:-$HOME/.nockguard/policy.yaml}"

# Which verifier applies is a property of the policy's signing settings
# (Ed25519 takes precedence over HMAC), not something to try in turn.
OUT=$(python3 - "$POLICY" <<'PY'
import os, sys, yaml
with open(sys.argv[1]) as f:
    audit = (yaml.safe_load(f) or {}).get("audit") or {}
base = os.path.basename(str(audit.get("path") or "audit.jsonl"))
if audit.get("sign_ed25519_key_env"):
    print("ed25519 -", base)
elif audit.get("sign_key_env"):
    print("hmac", audit["sign_key_env"], base)
else:
    print("none -", base)
PY
) || { echo "ERROR: could not read the signing settings from $POLICY (invalid YAML, or PyYAML missing)" >&2; exit 1; }
read -r SIGN HMAC_ENV BASE <<<"$OUT"

KEYS=$(compgen -G "$HOME/.nockguard/keys/*.pub" || true)
LOGS=$(compgen -G "$HOME/.nockguard/logs/*audit.jsonl" || true)
if [ ! -e "$TRAIL" ]; then
  # The .hwm file beside a trail outlives the trail, so it counts as evidence too.
  if [ -z "$KEYS$LOGS" ] && [ ! -e "$TRAIL.hwm" ]; then
    echo "SETUP: no trail at $TRAIL and no keys, other trails or .hwm file; auditing appears never to have run. Run the agent through nockguard, then scan again."
  else
    echo "HIGH: possible deletion. No trail at $TRAIL, but keys, other trails or a .hwm file exist. Find who removed it."
  fi
  exit 0
fi

# A per-agent trail is <agent>.<basename of audit.path> (AgentAuditPath) and is
# signed with that agent's own Ed25519 key. The name is only a guess when
# --audit chose the path: PER_AGENT=1 forces the per-agent verifier, PER_AGENT=0
# forces the policy verifier.
if [ "${PER_AGENT:-}" = 1 ] || { [ -z "${PER_AGENT:-}" ] && [ "$(basename "$TRAIL")" = "$AGENT.$BASE" ]; }; then
  SIGN=agent
fi

case "$SIGN" in
  agent) VERIFY=(nockguard verify --agent "$AGENT" --audit "$TRAIL") ;;
  ed25519) VERIFY=(nockguard verify --ed25519-pub-env "${PUB_ENV:-NOCKGUARD_AUDIT_ED25519_PUB}" --audit "$TRAIL") ;;
  hmac) VERIFY=(nockguard verify --key-env "$HMAC_ENV" --audit "$TRAIL") ;;
  *)
    echo "LOW: $TRAIL exists but the policy configures no signing and it is not a per-agent trail; nothing to verify; see finding 2h."
    exit 0 ;;
esac

# The verifier prints its verdict on stdout; exit 1 covers more than a missing key.
STATUS=0
RESULT=$("${VERIFY[@]}") || STATUS=$?
printf '%s\n' "$RESULT"
case "$STATUS" in
  0) echo "PROTECTED: chain intact" ;;
  1)
    # Match the verdict as a whole line, not as text inside another line.
    if printf '%s\n' "$RESULT" | grep -qx 'VERDICT: NO_ROWS'; then
      echo "MEDIUM: $TRAIL is empty (NO_ROWS); nothing is verified yet. Run the agent through nockguard, then scan again."
    elif printf '%s\n' "$RESULT" | grep -qx 'VERDICT: UNANCHORED'; then
      echo "MEDIUM: $TRAIL runs past its signed checkpoint (UNANCHORED); re-run once the writer is idle, and treat it as HIGH if it persists."
    else
      echo "HIGH: $TRAIL exists but could not be verified (missing public key or key env, or bad arguments); treat it as unverified"
    fi ;;
  2) echo "CRITICAL: tamper detected (chain broken, or the trail could not be opened)" ;;
  *) echo "ERROR: verifier exited $STATUS" >&2; exit 1 ;;
esac
```

Which verifier applies (Ed25519 takes precedence over HMAC, as in `AuditorForAgent` in `internal/policy/policy.go`):

| Trail and policy | Verifier |
|---|---|
| trail is `<agent>.<basename of audit.path>` (default `<agent>.audit.jsonl`), or `PER_AGENT=1`; `PER_AGENT=0` turns the name match off | `verify --agent` (public key from `NOCKGUARD_AGENT_<NAME>_ED25519_PUB` or `~/.nockguard/keys/<agent>.pub`) |
| `audit.sign_ed25519_key_env` set | `verify --ed25519-pub-env` |
| only `audit.sign_key_env` set | `verify --key-env <that name>` (HMAC) |
| none of the above | unsigned; nothing to verify (finding 2h) |

The trail's name decides the first row, because the per-agent path is only used when a per-agent key signs (`AuditorForAgent`): a key from `NOCKGUARD_AGENT_<NAME>_ED25519_KEY` always wins; a policy signing key wins over a `keygen` key file; otherwise the key file signs a per-agent trail. A per-agent key supplied only through the environment leaves no `.pub` file; set `NOCKGUARD_AGENT_<NAME>_ED25519_PUB` before verifying.

Exit codes (`runAudit` and `verifyAllAgents` in `cmd/nockguard/main.go`). The verifier selects the key before it opens the trail, so a missing public key or unset key env var exits 1 whether or not the trail exists (`requirePubHex` in `cmd/nockguard/keygen.go`). A trail that opens and verifies but is empty (`NO_ROWS`) or runs past its signed checkpoint (`UNANCHORED`) also exits 1 and prints `VERDICT: NO_ROWS` or `VERDICT: UNANCHORED` (`runAudit`), which is why the snippet reads the whole-line verdict before it labels an exit 1. Once the key is chosen, a trail that cannot be opened exits 2, the same as a broken chain (`audit.VerifyEd25519` returns the open error, and `runAudit` reports every error from it as TAMPER). That is why the snippet tests for the file first: exit 2 alone cannot tell a deleted trail from a forged one.

| Case | Severity |
|---|---|
| Trail present, verifier exits 0 | PROTECTED |
| Trail present, verifier exits 2 | **CRITICAL**: tamper detected. Check the file is readable by you (an unreadable file also exits 2), then escalate immediately and treat the chain as forensic evidence. |
| Trail present, verifier exits 1 with `VERDICT: NO_ROWS` | MEDIUM: the trail is empty, so nothing is verified. Not tampering; run the agent through nockguard and re-run. |
| Trail present, verifier exits 1 with `VERDICT: UNANCHORED` | MEDIUM: entries run past the signed checkpoint, usually a writer still active. Re-run once idle; HIGH if it persists. |
| Trail present, verifier exits 1 with no verdict line | HIGH: the trail cannot be verified (public key or key env missing). It is not tampering; supply the key and re-run. |
| Trail missing, and no keys, other trails or `<trail>.hwm` file | SETUP: auditing appears never to have run (a fresh install). Not a finding. A deletion that also wipes every one of those leaves the same picture; check `audit.enabled` and when the policy was deployed. |
| Trail missing, but keys, other trails or a `.hwm` file exist | HIGH: possible deletion. Never CRITICAL, because the code reports no tamper for an absent file. Look for who removed it; if the agent has genuinely never run since `keygen`, treat it as setup. |

`nockguard verify --all` checks every per-agent trail in the audit directory. It exits 2 if any trail is tampered, 1 if any trail is unverifiable or none are found (`NO_TRAILS`, which is not protection), and 0 only when all are intact. It cannot see a trail that was deleted: that trail is not in the glob. Run it as `STATUS=0; nockguard verify --all || STATUS=$?` and map `$STATUS` the same way.

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
