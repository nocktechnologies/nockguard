Lint a NockGuard policy file for structural and logic errors. Read the policy, check it against known anti-patterns, and report all issues before the user deploys it.

## How to invoke

```
/policy-lint [path]
```

If a path is provided, lint that file. Otherwise, lint `~/.nockguard/policy.yaml`.

## Step 1 — Read the policy

```bash
# Resolve the path
POLICY="${1:-${POLICY:-$HOME/.nockguard/policy.yaml}}"
[ -f "$POLICY" ] || { echo "No policy file found at $POLICY. Run \`nockguard init\` to scaffold one." >&2; exit 1; }
cat "$POLICY"
```

Run each snippet in this command as its own bash invocation; they `exit` non-zero on failure. Shells do not share variables, so every later snippet resolves `POLICY` itself (default `~/.nockguard/policy.yaml`); when the user gave a path, export `POLICY` to it before running each one.

Verify NockGuard can parse it. `nockguard policy check` runs the loader the proxy uses and nothing else: it starts no proxy, creates no trail, forwards nothing and reads no signing env, so its exit status means exactly "the policy loaded". It prints the load error on failure and, on success, the loader's `warning policy:` lines (for example a tool in more than one inject rule); report those as INFO.

```bash
POLICY="${POLICY:-$HOME/.nockguard/policy.yaml}"
command -v nockguard >/dev/null || { echo "ERROR: nockguard is not on PATH; cannot run the parse check" >&2; exit 1; }
STATUS=0
OUT=$(nockguard policy check --policy "$POLICY" 2>&1) || STATUS=$?
case "$STATUS" in
  0) if [ -n "$OUT" ]; then printf '%s\n' "$OUT"; fi ;;
  126|127) echo "ERROR: the parse check could not be launched (exit $STATUS); this says nothing about the policy" >&2; exit 1 ;;
  *) case "$OUT" in
       *"unknown policy command: check"*) echo "ERROR: this nockguard is too old for \`policy check\`; upgrade it. This says nothing about the policy" >&2 ;;
       *) printf '%s\n' "$OUT" >&2; echo "ERROR: nockguard could not load $POLICY (exit $STATUS)" >&2 ;;
     esac
     exit 1 ;;
esac
```

A non-zero status is an **ERROR**; stop, because the remaining checks require a valid file. The loader decodes with `KnownFields(true)` (`loadFrom` in `internal/policy/policy.go`), so an unknown key anywhere, a malformed tool glob, an unknown `validate_input` category or a bad `rate_limit.window` is a load failure, not a silent no-op. The check does not exercise the audit settings' environment (signing keys, forwarding); E005 and E006 cover them. The checks below name the likely cause and cover what the loader does not reject.

## Step 2 — Schema checks

### E001 — Unknown top-level keys (ERROR)

The only valid top-level keys are `agents` and `audit`. Any other key makes the policy fail to load (strict YAML decoding, `KnownFields(true)`) and is likely a typo.

```bash
POLICY="${POLICY:-$HOME/.nockguard/policy.yaml}"
python3 -c "
import yaml, sys
with open('$POLICY') as f:
    doc = yaml.safe_load(f) or {}
known = {'agents', 'audit'}
extra = set(doc or {}) - known
if extra:
    print('Unknown keys:', extra)
" || { echo "policy-lint: check E001 failed to run (exit $?); do not read this as a pass" >&2; exit 1; }
```

### E002 — Unknown agent-policy keys (ERROR)

Valid keys under each agent: `allow`, `deny`, `ask`, `shadow`, `mode`, `fail_mode`, `validate_input`, `block_params`, `rate_limit`, `spend_cap`, `trust`, `require_approval` (legacy; prefer `ask`), `inject`. Anything else makes the policy fail to load. Source: `AgentPolicy` in `internal/policy/policy.go`.

```bash
POLICY="${POLICY:-$HOME/.nockguard/policy.yaml}"
python3 -c "
import yaml, sys
with open('$POLICY') as f:
    doc = yaml.safe_load(f) or {}
valid = {'allow','deny','ask','shadow','mode','fail_mode','validate_input','block_params','rate_limit','spend_cap','trust','require_approval','inject'}
for agent, pol in (doc.get('agents') or {}).items():
    if not isinstance(pol, dict): continue
    extra = set(pol) - valid
    if extra:
        print(f'Agent {agent!r}: unknown keys {extra}')
" || { echo "policy-lint: check E002 failed to run (exit $?); do not read this as a pass" >&2; exit 1; }
```

### E003 — Invalid mode or fail_mode value (ERROR)

`mode` must be `"allow"` or `"deny"`; `fail_mode` must be `"deny"` (default) or `"ask"`. The loader does not validate these values. An unrecognised `mode` behaves like an omitted one: with no `allow` list the agent is denied every tool (`default-deny (no allow list)`); with an `allow` list `mode` is not consulted. Any `fail_mode` other than `"ask"` behaves as `"deny"`. Either way the operator's intent is lost, so flag it.

```bash
POLICY="${POLICY:-$HOME/.nockguard/policy.yaml}"
python3 -c "
import yaml
with open('$POLICY') as f:
    doc = yaml.safe_load(f) or {}
for agent, pol in (doc.get('agents') or {}).items():
    pol = pol or {}
    m = pol.get('mode')
    if m is not None and m not in ('allow', 'deny'):
        print(f'Agent {agent!r}: invalid mode {m!r} (must be allow or deny)')
    fm = pol.get('fail_mode')
    if fm is not None and fm not in ('deny', 'ask'):
        print(f'Agent {agent!r}: invalid fail_mode {fm!r} (must be deny or ask)')
" || { echo "policy-lint: check E003 failed to run (exit $?); do not read this as a pass" >&2; exit 1; }
```

### E004 — rate_limit missing window (ERROR)

A `rate_limit` block without a positive Go-duration `window` (`30s`, `1m`, `1h`) is rejected when the policy loads (`rateLimitWindow` in `internal/policy/policy.go`).

```bash
POLICY="${POLICY:-$HOME/.nockguard/policy.yaml}"
python3 -c "
import yaml
with open('$POLICY') as f:
    doc = yaml.safe_load(f) or {}
for agent, pol in (doc.get('agents') or {}).items():
    rl = (pol or {}).get('rate_limit')
    if isinstance(rl, dict) and not rl.get('window'):
        print(f'Agent {agent!r}: rate_limit has no window')
" || { echo "policy-lint: check E004 failed to run (exit $?); do not read this as a pass" >&2; exit 1; }
```

### E005 — audit.sign_key_env or sign_ed25519_key_env set but env var unset (WARNING)

If signing is configured but the env var is missing, NockGuard fails at startup.

```bash
POLICY="${POLICY:-$HOME/.nockguard/policy.yaml}"
python3 -c "
import yaml, os
with open('$POLICY') as f:
    doc = yaml.safe_load(f) or {}
audit = (doc or {}).get('audit') or {}
for key in ('sign_key_env', 'sign_ed25519_key_env'):
    env_name = audit.get(key)
    if env_name and not os.environ.get(env_name):
        print(f'audit.{key} references {env_name!r} but that env var is not set')
" || { echo "policy-lint: check E005 failed to run (exit $?); do not read this as a pass" >&2; exit 1; }
```

### E006 — audit.forward.api_key_env set but env var unset (WARNING)

```bash
POLICY="${POLICY:-$HOME/.nockguard/policy.yaml}"
python3 -c "
import yaml, os
with open('$POLICY') as f:
    doc = yaml.safe_load(f) or {}
fwd = ((doc or {}).get('audit') or {}).get('forward') or {}
if fwd.get('enabled'):
    if not fwd.get('url'):
        print('audit.forward.enabled is true but url is missing')
    env_name = fwd.get('api_key_env')
    if env_name and not os.environ.get(env_name):
        print(f'audit.forward.api_key_env references {env_name!r} but that env var is not set')
" || { echo "policy-lint: check E006 failed to run (exit $?); do not read this as a pass" >&2; exit 1; }
```

## Step 3 — Logic checks

### W001 — Allow-all agent (WARNING)

An agent with no `allow` list and `mode: allow` permits every tool that is not denied. This is almost never intended. (An agent with no `allow` list and `mode` omitted or `deny` is the opposite: every tool is denied, see W006.)

```bash
POLICY="${POLICY:-$HOME/.nockguard/policy.yaml}"
python3 -c "
import yaml
with open('$POLICY') as f:
    doc = yaml.safe_load(f) or {}
for agent, pol in (doc.get('agents') or {}).items():
    pol = pol or {}
    if not pol.get('allow') and pol.get('mode') == 'allow':
        print(f'Agent {agent!r}: no allow list and mode is allow — allow-all')
" || { echo "policy-lint: check W001 failed to run (exit $?); do not read this as a pass" >&2; exit 1; }
```

### W002 — Bare wildcard in allow list (WARNING)

`"*"` in allow matches every tool name, including destructive ones:

```bash
POLICY="${POLICY:-$HOME/.nockguard/policy.yaml}"
python3 -c "
import yaml
with open('$POLICY') as f:
    doc = yaml.safe_load(f) or {}
for agent, pol in (doc.get('agents') or {}).items():
    for pat in (pol or {}).get('allow') or []:
        if pat == '*':
            print(f'Agent {agent!r}: allow contains bare wildcard \"*\" — allows ALL tools')
" || { echo "policy-lint: check W002 failed to run (exit $?); do not read this as a pass" >&2; exit 1; }
```

### W003 — Deny rule shadowed by allow (INFO)

An allow pattern that is broader than a deny pattern may reach tools the deny was meant to block — but since deny always wins, this is a readability issue, not a logic error. Flag it so the operator knows the deny is redundant if the intent was to block that tool via the allow side.

```bash
POLICY="${POLICY:-$HOME/.nockguard/policy.yaml}"
python3 -c "
import yaml, fnmatch
with open('$POLICY') as f:
    doc = yaml.safe_load(f) or {}
for agent, pol in (doc.get('agents') or {}).items():
    pol = pol or {}
    for deny_pat in pol.get('deny') or []:
        for allow_pat in pol.get('allow') or []:
            if fnmatch.fnmatch(deny_pat, allow_pat):
                print(f'Agent {agent!r}: deny rule {deny_pat!r} would be matched by allow pattern {allow_pat!r} — deny wins, but this may be confusing')
" || { echo "policy-lint: check W003 failed to run (exit $?); do not read this as a pass" >&2; exit 1; }
```

### W006 — Agent that denies every tool (INFO)

A named agent with no `allow` list, `mode` omitted or `deny`, and no `ask` (or legacy `require_approval`) rules is denied every tool (`default-deny (no allow list)` / `mode "deny", no allow list`). That is the right shape for `default`, but on a working agent it usually means a forgotten `allow` list.

```bash
POLICY="${POLICY:-$HOME/.nockguard/policy.yaml}"
python3 -c "
import yaml
with open('$POLICY') as f:
    doc = yaml.safe_load(f) or {}
for agent, pol in (doc.get('agents') or {}).items():
    pol = pol or {}
    if agent != 'default' and not pol.get('allow') and not pol.get('ask') and not pol.get('require_approval') and pol.get('mode') != 'allow':
        print(f'Agent {agent!r}: no allow list and mode is not allow — every tool is denied')
" || { echo "policy-lint: check W006 failed to run (exit $?); do not read this as a pass" >&2; exit 1; }
```

### W004 — No default agent (INFO)

Without a `default` entry, any unrecognized `--agent` value fails-closed (all tools denied). This is safe but can be surprising. Add `default: { mode: deny }` as an explicit backstop.

```bash
POLICY="${POLICY:-$HOME/.nockguard/policy.yaml}"
python3 -c "
import yaml
with open('$POLICY') as f:
    doc = yaml.safe_load(f) or {}
if 'default' not in (doc.get('agents') or {}):
    print('No default agent policy — unrecognized agents fail-closed (safe but implicit). Consider adding: default: { mode: deny }')
" || { echo "policy-lint: check W004 failed to run (exit $?); do not read this as a pass" >&2; exit 1; }
```

### W005 — ask / require_approval with no approver configured (WARNING)

`ask` (and legacy `require_approval`) rules need an approver: the Telegram bot (`NOCKGUARD_APPROVAL_BOT_TOKEN` and `NOCKGUARD_APPROVAL_CHAT_ID`) or the local approver (`NOCKGUARD_APPROVER=local`). With neither, every such call is denied, so the tool is effectively unusable. The policy file gives no indication.

```bash
POLICY="${POLICY:-$HOME/.nockguard/policy.yaml}"
python3 -c "
import yaml, os
with open('$POLICY') as f:
    doc = yaml.safe_load(f) or {}
for agent, pol in (doc.get('agents') or {}).items():
    pol = pol or {}
    if pol.get('ask') or pol.get('require_approval'):
        telegram = all(os.environ.get(v) for v in ('NOCKGUARD_APPROVAL_BOT_TOKEN', 'NOCKGUARD_APPROVAL_CHAT_ID'))
        if not (telegram or os.environ.get('NOCKGUARD_APPROVER') == 'local'):
            print(f'Agent {agent!r}: ask/require_approval is set but no approver is configured — those calls will be denied')
            break
" || { echo "policy-lint: check W005 failed to run (exit $?); do not read this as a pass" >&2; exit 1; }
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

A policy with zero errors loads (the loader has already rejected anything structurally invalid). Warnings should be reviewed but do not block deployment.
