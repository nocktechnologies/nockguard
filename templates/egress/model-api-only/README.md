# NockGuard Egress Template: Model API Only

This template runs NockGuard as an HTTP/HTTPS forward proxy for model/API
egress. Phase 1 is observe-only: every destination host is policy-evaluated and
signed into the audit chain, but requests are never blocked.

## Files

- `CLAUDE.md` - agent identity reminder for egress-audited sessions.
- `egress-policy.yaml` - deny-by-default host allowlist for model API and NockCC.
- `.claude/commands/egress-audit.md` - quick audit verification command.

## Setup

Generate an Ed25519 audit keypair (written to `~/.nockguard/keys/default.ed25519` and `default.pub`; the seed is never printed):

```bash
nockguard keygen
```

Load both into the proxy environment straight from the files:

```bash
export NOCKGUARD_AUDIT_ED25519_KEY="$(cat ~/.nockguard/keys/default.ed25519)"
export NOCKGUARD_AUDIT_ED25519_PUB="$(cat ~/.nockguard/keys/default.pub)"
```

Start the proxy:

```bash
nockguard egress-proxy \
  --listen 127.0.0.1:8899 \
  --agent model-api-only \
  --policy templates/egress/model-api-only/egress-policy.yaml \
  --audit .nockguard/logs/egress-audit.jsonl
```

Point the agent process at the proxy:

```bash
export HTTP_PROXY=http://127.0.0.1:8899
export HTTPS_PROXY=http://127.0.0.1:8899
export NO_PROXY=localhost,127.0.0.1
```

## Phase 1 Behavior

Allowed hosts are recorded as `allow` audit events. Hosts outside the allowlist
are recorded as `deny` audit events and logged as `WOULD-BLOCK
(observe-only)`, but the request still goes through.

Do not treat Phase 1 as a containment control. It is an accountability and
profile-validation mode. Phase 2 can turn deny decisions into blocks only after
the Phase 1 audit trail shows no legitimate false-denies.

## Verify The Audit Chain

```bash
nockguard audit verify \
  --ed25519-pub-env NOCKGUARD_AUDIT_ED25519_PUB \
  --audit .nockguard/logs/egress-audit.jsonl
```
