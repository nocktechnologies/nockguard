# NockGuard Pool Router (`nockguard-pool`)

Status: **V1 in development** (this document is the design contract — the code
ships against it, and any behavior not documented here is a bug).

NockGuard's promise is that every agent action passes through an accountable
gate. The MCP proxy covers *tool calls*; the pool router covers the other half
of what an agent does: *model traffic*. It pools multiple Codex subscriptions
behind one local endpoint and routes each request to the account with headroom,
so multi-subscription fleets stop hand-switching `--codex-home` — with every
routing decision audited, signed, and visible.

## Full disclosure — everything this component does

This section is the contract. If the binary does something not listed here,
that is a bug to be reported and fixed, not a feature.

**It does:**

1. Listen on a localhost port (never a public interface by default).
2. Reverse-proxy Codex backend traffic (`/backend-api/codex/*`) to one of the
   configured upstream accounts, streaming SSE responses through unmodified.
3. Read each upstream's OAuth tokens from that account's `auth.json` (the
   standard Codex CLI credential file in each configured `codex_home`).
4. Observe rate-limit metadata that the Codex backend self-reports on
   responses passing through (`x-codex-*` usage headers and rate-limit SSE
   events) and keep an in-memory picture of each account's remaining headroom.
5. Route by: (a) session stickiness first — an established conversation always
   returns to the account that holds its server-side state; (b) otherwise
   maximum quota headroom; (c) a temporary cooldown demotes an account that
   just failed (rate-limited / 5xx / auth error).
6. Write one signed audit event per routing decision (see "Audit events").
7. Refresh an upstream's OAuth token on auth failure and persist the rotated
   token back to that account's own `auth.json`.

**It does NOT:**

- Log, store, or inspect prompt or response *content*. Bodies stream through;
  routing uses headers and event metadata only.
- Store credentials anywhere outside each account's own `auth.json`.
- Phone home, collect telemetry, or make any network connection other than
  (a) the configured upstreams and (b) the optional NockCC audit forward you
  explicitly configure.
- Listen on non-localhost interfaces unless you explicitly configure it to.
- Share, multiplex, or resell account access. It routes one operator's own
  subscriptions for that operator's own agents.

## What is stored, exactly

| Data | Where | Contents |
|---|---|---|
| Audit events | Signed JSONL (existing NockGuard audit trail) | timestamp, agent, model, chosen account *label*, decision, reason, latency, HTTP status. **No prompt text, no tokens, no account emails.** |
| Quota state | Memory only (lost on restart) | per-account used-percent, window, reset-at, as self-reported by the backend |
| Session pins | Memory only (V1) | session-id → account label |
| Credentials | Never stored by the router | read from each `codex_home`'s `auth.json`; rotated tokens written back to the same file and nowhere else |

## Configuration (`pool.yaml`)

```yaml
pool:
  listen: "127.0.0.1:4141"   # localhost only; changing this is on you
  upstreams:
    - label: sub-1            # the name that appears in audit events
      codex_home: ~/.codex
    - label: sub-2
      codex_home: ~/.codex-sub2
  routing:
    strategy: headroom        # max remaining quota; sticky sessions always win
    cooldown_seconds: 60      # demotion window after an upstream failure

# The audit block is the same one the MCP proxy uses — same signing, same
# verification, same Wall. See README "Audit trail".
audit:
  enabled: true
  sign_ed25519_key_env: NOCKGUARD_ED25519_KEY
```

## Audit events

Route decisions reuse the existing signed JSONL trail (`internal/audit`), so
`nockguard audit verify` covers them and the Live Wall renders them. V1 event
shape (one per routed request):

```json
{"ts":"...","agent":"<caller>","tool":"pool:route","decision":"allow",
 "reason":"sticky-session sub-1" ,"sig":"..."}
```

Reason strings are enumerated, not free text: `sticky-session <label>`,
`max-headroom <label>`, `cooldown-skip <label>`, `refresh-retry <label>`,
`all-upstreams-exhausted`.

## Client setup

Each agent's Codex CLI `config.toml` points at the pool once; `--codex-home`
hand-switching ends:

```toml
[model_providers.nockguard_pool]
name = "NockGuard Pool"
base_url = "http://127.0.0.1:4141"
wire_api = "responses"
```

## Threat model notes

- Anyone who can reach the listen port can spend your subscriptions — V1
  binds localhost and ships no remote story on purpose. Put it on Tailscale
  yourself only if you understand that trade.
- The router holds decrypted access tokens in memory while proxying, exactly
  as the Codex CLI itself does.
- `auth.json` files remain the single source of credential truth; back them
  up before first use. Token refresh rewrites them in place.

## V1 scope fence

In scope: HTTP/SSE pass-through, 2+ upstreams, sticky sessions, headroom
routing, cooldown demotion, refresh-on-401, signed audit events.
Out of scope (documented so their absence is legible): WebSockets, pool API
keys, multi-operator pools, persistent session pins, prompt-cache locality
routing, any UI beyond the Wall panel.
