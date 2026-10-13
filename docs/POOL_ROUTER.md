# NockGuard Pool Router (`nockguard-pool`)

**Status: scaffold — `serve` refuses to run; the sections below describe the design, not current behavior.**

`nockguard-pool validate` loads and checks config today.

The MCP proxy covers *tool calls*. The planned pool router would cover *model
traffic*: pool multiple Codex subscriptions behind one local endpoint and route
each request to an account with headroom, with routing decisions audited.

## Target V1 contract

This section specifies the planned routing behavior. Runtime behavior today is
limited to config validation and refusing `serve`.

**Target V1 behavior:**

1. Listen on a localhost port (never a public interface by default).
2. Reverse-proxy Codex backend traffic (`/backend-api/codex/*`) to one of the
   configured upstream accounts, streaming SSE responses through unmodified.
3. Read each upstream's OAuth tokens from that account's `auth.json` (the
   standard Codex CLI credential file in each configured `codex_home`).
4. Observe rate-limit metadata that the Codex backend self-reports on
   responses passing through (`x-codex-*` usage headers and rate-limit SSE
   events) and keep an in-memory picture of each account's remaining headroom.
5. Route by: (a) session stickiness first — an established conversation would
   return to the account that holds its server-side state; (b) otherwise
   maximum quota headroom; (c) a temporary cooldown would demote an account
   that just failed (rate-limited / 5xx / auth error).
6. When budget config is present, aggregate configured call cost across the
   `rootSessionID` spawn tree. At or above the cap, route to the best cheap
   upstream instead of killing the request.
7. Emit budget threshold asks and downgrade events to the optional NockCC Live
   Wall forwarder when it is configured.
8. Write one signed audit event per routing decision (see "Audit events").
9. Refresh an upstream's OAuth token on auth failure and persist the rotated
   token back to that account's own `auth.json`.

**Target V1 exclusions:**

- Log, store, or inspect prompt or response *content*. Bodies would stream
  through; routing would use headers and event metadata only.
- Store credentials anywhere outside each account's own `auth.json`.
- Phone home, collect telemetry, or make any network connection other than
  (a) the configured upstreams and (b) the optional NockCC audit forward you
  explicitly configure.
- Listen on non-localhost interfaces unless you explicitly configure it to.
- Share, multiplex, or resell account access. It would route one operator's own
  subscriptions for that operator's own agents.

## Target V1 storage

| Data | Where | Contents |
|---|---|---|
| Audit events | Would use signed JSONL (existing NockGuard audit format) | timestamp, agent, model, chosen account *label*, decision, reason, latency, HTTP status. **No prompt text, no tokens, no account emails.** |
| Quota state | Would be in memory only (lost on restart) | per-account used-percent, window, reset-at, as self-reported by the backend |
| Session pins | Would be in memory only (V1) | session-id → account label |
| Budget state | Would be in memory only (lost on restart) | rootSessionID → configured spend total, plus one threshold-ask marker per root/threshold |
| Credentials | Would remain in each account's `auth.json` | the router would read each `codex_home` file and write rotated tokens back only to that file |

## Configuration (`pool.yaml`)

```yaml
pool:
  listen: "127.0.0.1:4141"   # localhost only; changing this is on you
  upstreams:
    - label: sub-1            # the name that appears in audit events
      codex_home: ~/.codex
      tier: cheap             # cheap | standard | expensive; empty = expensive
      cost_per_call_usd: 0.01 # configured estimate added to rootSessionID spend
    - label: sub-2
      codex_home: ~/.codex-sub2
      tier: expensive
      cost_per_call_usd: 0.10
  routing:
    strategy: headroom        # planned: max remaining quota; sticky sessions first
    cooldown_seconds: 60      # demotion window after an upstream failure
  budget:
    max_cost_usd: 1.00        # planned: absent or 0 disables budget routing
    ask_thresholds_usd: [0.50, 0.75]

# Target V1 would use the MCP proxy's audit block and signing format.
# See README "Audit trail".
audit:
  enabled: true
  sign_ed25519_key_env: NOCKGUARD_ED25519_KEY
```

## Audit events

Route decisions would use the existing signed JSONL format (`internal/audit`),
so `nockguard audit verify` would cover them and the Live Wall would render
them. Target V1 event shape (one per routed request):

```json
{"ts":"...","agent":"<caller>","tool":"pool:route","decision":"allow",
 "reason":"sticky-session sub-1" ,"sig":"..."}
```

Reason strings would be enumerated, not free text: `sticky-session <label>`,
`max-headroom <label>`, `cooldown-skip <label>`, `budget-downgrade <label>`,
`budget-no-cheap-upstreams`, `refresh-retry <label>`,
`all-upstreams-exhausted`.

## Budget and downgrade semantics

Budget routing would be opt-in. If `pool.budget.max_cost_usd` were absent or
`0`, routing would use the base `Route` behavior and record no spend.

With budget routing enabled, the router would:

- Add each routed call's configured `cost_per_call_usd` to the `rootSessionID`
  tree. Without a root, it would use the session id, then a process-local
  default bucket.
- Emit at most one `budget-ask` event per root for each configured
  `ask_thresholds_usd` value. The ask would signal the Live Wall without
  blocking the route.
- Exclude expensive and untiered upstreams once tree spend reached
  `max_cost_usd`, choosing the eligible cheap upstream with the best headroom
  while respecting cooldowns.
- Treat untiered upstreams as expensive so a new model without a tier could
  not bypass the cap.
- Prefer downgrade when a cheap upstream was available: at-cap routing would
  return `budget-downgrade <label>`. It would return `ErrAllExhausted` only
  when every eligible cheap upstream was unavailable.

## Client setup

Once `serve` exists, each agent's Codex CLI `config.toml` would point at the
pool, removing the need to switch `--codex-home` by hand:

```toml
[model_providers.nockguard_pool]
name = "NockGuard Pool"
base_url = "http://127.0.0.1:4141"
wire_api = "responses"
```

## Threat model notes

- Anyone who could reach the planned listen port could spend your
  subscriptions. V1 would bind localhost and provide no remote setup.
- The router would hold decrypted access tokens in memory while proxying,
  as the Codex CLI does.
- `auth.json` files would remain the credential source; token refresh would
  rewrite them in place.

## V1 scope fence

Target V1 scope: HTTP/SSE pass-through, 2+ upstreams, sticky sessions, headroom
routing, cooldown demotion, refresh-on-401, signed audit events.
Outside target V1: WebSockets, pool API
keys, multi-operator pools, persistent session pins, prompt-cache locality
routing, any UI beyond the Wall panel.
