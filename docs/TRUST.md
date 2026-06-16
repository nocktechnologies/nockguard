# NockGuard Behavioral Trust

Status: **opt-in**. Missing or disabled `trust` config preserves the existing
static rate-limit behavior.

Behavioral trust turns the decisions NockGuard already records into a per-agent
score. It is deliberately not a second audit ledger: NockGuard's hash-chained
audit trail remains the source of evidence. Trust is only a live control signal
for rate-limit headroom.

## Score Model

Each agent starts at the neutral baseline score of `0.5`.

| Decision outcome | Score delta |
|---|---:|
| allow | `+0.01` |
| warn | `-0.02` |
| deny | `-0.05` |

The punishment/reward ratio is intentionally asymmetric: one deny offsets five
allows. This makes runaway or hostile behavior reduce headroom quickly while
still allowing recovery.

NockGuard maps the existing proxy decision strings into outcomes:

| Proxy decision | Trust outcome |
|---|---|
| `allow`, `approval-granted` | allow |
| `warn`, `ratelimit`, `block`, `approval-denied` | warn |
| `deny` | deny |

Other audit-only decisions such as `hide` and `state-write` do not affect trust.

## Decay

Scores decay lazily back to `0.5` over 60 seconds. Decay is computed on access,
not by a timer. Every update performs decay before applying the new decision
delta, and reads also decay before returning the current score. This makes
recovery automatic without adding background goroutines or wall-clock races.

## Rate Multipliers

Trust scales only the configured `rate_limit.max_calls` cap. Spend caps are not
changed.

| Score | Tier | Rate multiplier |
|---:|---|---:|
| `>= 0.8` | excellent | `2.0x` |
| `>= 0.5` | normal | `1.0x` |
| `>= 0.3` | reduced | `0.5x` |
| `< 0.3` | restricted | `0.1x` |

The adjusted cap is rounded up, with a minimum of 1 when the base cap is
positive.

## Configuration

Trust is configured per agent:

```yaml
agents:
  kit:
    allow: ["nockcc_nock_*"]
    rate_limit:
      max_calls: 60
      window: 1m
    trust:
      enabled: true
```

When enabled, scores persist at `~/.nockguard/trust/<agent>.json` by default.
Use `path` only for tests or explicit operational placement:

```yaml
trust:
  enabled: true
  path: /var/lib/nockguard/trust/kit.json
```

Inspect a score with:

```bash
nockguard trust show --agent kit
```
