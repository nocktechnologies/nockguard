# NockGuard Egress Template: Model API Only

This template runs NockGuard as an HTTP/HTTPS forward proxy for model/API
egress. By default it is observe-only: every destination host is policy-evaluated
and signed into the audit chain, and a policy denial is only recorded (add
`--enforce` to block it). The SSRF guard always rejects private and unsafe
destinations.

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

## Observe mode (default) and `--enforce`

Allowed hosts are recorded as `allow` audit events. Hosts outside the allowlist
are recorded as `deny` audit events and logged as `WOULD-BLOCK
(observe-only)`, but the request still goes through. The SSRF guard is active in
both modes: loopback, private, link-local and other unsafe destinations get
`403 blocked: SSRF guard` regardless.

Observe mode is not a containment control. It is an accountability and
profile-validation mode. Once the audit trail shows no legitimate false-denies,
add `--enforce` to the `nockguard egress-proxy` command: a host outside the
allowlist then gets `403 forbidden by egress policy`. The audit event is `deny`
in both modes. Clients that ignore `HTTP_PROXY` / `HTTPS_PROXY` bypass the proxy
either way; see `docs/how-it-works/egress-proxy.md` (Source:
`internal/proxy/forwardhttp/forwardhttp.go`).

## Verify The Audit Chain

```bash
nockguard audit verify \
  --ed25519-pub-env NOCKGUARD_AUDIT_ED25519_PUB \
  --audit .nockguard/logs/egress-audit.jsonl
```
