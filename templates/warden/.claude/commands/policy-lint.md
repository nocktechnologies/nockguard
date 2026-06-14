Lint a NockGuard policy file for structural and logic errors. Read the policy, check it against known anti-patterns, and report all issues before the user deploys it.

## How to invoke

```
/policy-lint [path]
```

If a path is provided, lint that file. Otherwise, lint `~/.nockguard/policy.yaml`.

## Step 1 — Read the policy

```bash
# Resolve the path
POLICY="${1:-$HOME/.nockguard/policy.yaml}"
cat "$POLICY"
```

If the file does not exist, stop: "No policy file found at $POLICY. Run `nockguard init` to scaffold one."

Verify NockGuard can parse it:

```bash
# Proxy exits non-zero if the policy fails to load
nockguard proxy --upstream "echo" --agent lint-probe --policy "$POLICY" 2>&1 | head -5
```

If this exits with a parse error, report it as **ERROR** and stop — the remaining checks require a valid file.

## Step 2 — Schema checks

### E001 — Unknown top-level keys (ERROR)

The only valid top-level keys are `agents` and `audit`. Any other key is a silent no-op (NockGuard's YAML unmarshaler ignores unknown fields) and likely a typo.

```bash
python3 -c "
import yaml, sys
with open('$POLICY') as f:
    doc = yaml.safe_load(f)
known = {'agents', 'audit'}
extra = set(doc or {}) - known
if extra:
    print('Unknown keys:', extra)
" 2>/dev/null
```

### E002 — Unknown agent-policy keys (ERROR)

Valid keys under each agent: `allow`, `deny`, `mode`, `validate_input`, `block_params`, `rate_limit`, `spend_cap`, `require_approval`. Anything else is silently ignored.

```bash
python3 -c "
import yaml, sys
with open('$POLICY') as f:
    doc = yaml.safe_load(f)
valid = {'allow','deny','mode','validate_input','block_params','rate_limit','spend_cap','require_approval'}
for agent, pol in (doc.get('agents') or {}).items():
    if not isinstance(pol, dict): continue
    extra = set(pol) - valid
    if extra:
        print(f'Agent {agent!r}: unknown keys {extra}')
" 2>/dev/null
```

### E003 — Invalid mode value (ERROR)

`mode` must be `"allow"` or `"deny"`. Any other value falls through to `"allow"` (the default), which may not be what the operator intended.

```bash
python3 -c "
import yaml
with open('$POLICY') as f:
    doc = yaml.safe_load(f)
for agent, pol in (doc.get('agents') or {}).items():
    m = (pol or {}).get('mode')
    if m is not None and m not in ('allow', 'deny'):
        print(f'Agent {agent!r}: invalid mode {m!r} (must be allow or deny)')
" 2>/dev/null
```

### E004 — rate_limit missing window (ERROR)

A `rate_limit` block without a `window` will fail at startup.

```bash
python3 -c "
import yaml
with open('$POLICY') as f:
    doc = yaml.safe_load(f)
for agent, pol in (doc.get('agents') or {}).items():
    rl = (pol or {}).get('rate_limit')
    if isinstance(rl, dict) and not rl.get('window'):
        print(f'Agent {agent!r}: rate_limit has no window')
" 2>/dev/null
```

### E005 — audit.sign_key_env or sign_ed25519_key_env set but env var unset (WARNING)

If signing is configured but the env var is missing, NockGuard fails at startup.

```bash
python3 -c "
import yaml, os
with open('$POLICY') as f:
    doc = yaml.safe_load(f)
audit = (doc or {}).get('audit') or {}
for key in ('sign_key_env', 'sign_ed25519_key_env'):
    env_name = audit.get(key)
    if env_name and not os.environ.get(env_name):
        print(f'audit.{key} references {env_name!r} but that env var is not set')
" 2>/dev/null
```

### E006 — audit.forward.api_key_env set but env var unset (WARNING)

```bash
python3 -c "
import yaml, os
with open('$POLICY') as f:
    doc = yaml.safe_load(f)
fwd = ((doc or {}).get('audit') or {}).get('forward') or {}
if fwd.get('enabled'):
    if not fwd.get('url'):
        print('audit.forward.enabled is true but url is missing')
    env_name = fwd.get('api_key_env')
    if env_name and not os.environ.get(env_name):
        print(f'audit.forward.api_key_env references {env_name!r} but that env var is not set')
" 2>/dev/null
```

## Step 3 — Logic checks

### W001 — Implicit allow-all agent (WARNING)

An agent with no `allow` list and `mode` not set to `deny` permits every tool. This is almost never intended.

```bash
python3 -c "
import yaml
with open('$POLICY') as f:
    doc = yaml.safe_load(f)
for agent, pol in (doc.get('agents') or {}).items():
    pol = pol or {}
    if not pol.get('allow') and pol.get('mode') != 'deny':
        print(f'Agent {agent!r}: no allow list and mode is not deny — implicit allow-all')
" 2>/dev/null
```

### W002 — Bare wildcard in allow list (WARNING)

`"*"` in allow matches every tool name, including destructive ones:

```bash
python3 -c "
import yaml
with open('$POLICY') as f:
    doc = yaml.safe_load(f)
for agent, pol in (doc.get('agents') or {}).items():
    for pat in (pol or {}).get('allow') or []:
        if pat == '*':
            print(f'Agent {agent!r}: allow contains bare wildcard \"*\" — allows ALL tools')
" 2>/dev/null
```

### W003 — Deny rule shadowed by allow (INFO)

An allow pattern that is broader than a deny pattern may reach tools the deny was meant to block — but since deny always wins, this is a readability issue, not a logic error. Flag it so the operator knows the deny is redundant if the intent was to block that tool via the allow side.

```bash
python3 -c "
import yaml, fnmatch
with open('$POLICY') as f:
    doc = yaml.safe_load(f)
for agent, pol in (doc.get('agents') or {}).items():
    pol = pol or {}
    for deny_pat in pol.get('deny') or []:
        for allow_pat in pol.get('allow') or []:
            if fnmatch.fnmatch(deny_pat, allow_pat):
                print(f'Agent {agent!r}: deny rule {deny_pat!r} would be matched by allow pattern {allow_pat!r} — deny wins, but this may be confusing')
" 2>/dev/null
```

### W004 — No default agent (INFO)

Without a `default` entry, any unrecognized `--agent` value fails-closed (all tools denied). This is safe but can be surprising. Add `default: { mode: deny }` as an explicit backstop.

```bash
python3 -c "
import yaml
with open('$POLICY') as f:
    doc = yaml.safe_load(f)
if 'default' not in (doc.get('agents') or {}):
    print('No default agent policy — unrecognized agents fail-closed (safe but implicit). Consider adding: default: { mode: deny }')
" 2>/dev/null
```

### W005 — require_approval with no approval bot configured (WARNING)

`require_approval` rules are silently un-enforced if neither `NOCKGUARD_APPROVAL_BOT_TOKEN` nor `NOCKGUARD_APPROVAL_CHAT_ID` is set. The proxy logs this at startup but the policy file gives no indication.

```bash
python3 -c "
import yaml, os
with open('$POLICY') as f:
    doc = yaml.safe_load(f)
for agent, pol in (doc.get('agents') or {}).items():
    if (pol or {}).get('require_approval'):
        if not (os.environ.get('NOCKGUARD_APPROVAL_BOT_TOKEN') and os.environ.get('NOCKGUARD_APPROVAL_CHAT_ID')):
            print(f'Agent {agent!r}: require_approval is set but approval bot env vars are not configured — gates will be un-enforced')
            break
" 2>/dev/null
```

## Step 4 — Report

List findings grouped by severity: ERROR → WARNING → INFO.

For each finding:
```
[LEVEL] W003 — Deny rule shadowed by allow
Agent: my-agent
Pattern: allow "*_list" shadows intent of deny "nockcc_list_private"
Fix: deny always wins — if this is intentional, no change needed; otherwise rename the allow pattern.
```

End with a pass/fail summary: "X errors, Y warnings, Z info. Policy is [READY TO DEPLOY / NOT READY — fix errors first]."

A policy with zero errors is safe to load. Warnings should be reviewed but do not block deployment.
