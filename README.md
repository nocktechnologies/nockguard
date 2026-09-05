# NockGuard

**The MCP firewall.** Put NockGuard in front of any MCP server and every tool call your agent makes is policy-checked, blocked when it should be, and written to a signed audit trail nobody can quietly edit — including you.

Every agent connector is untrusted until proven otherwise. NockGuard is how you prove it.

```
Agent (Claude Code, Codex, Cursor, any MCP client)
    |
    v
NockGuard  ── allow / deny / ask ──▶  signed audit trail  ──▶  `nockguard verify`
    |
    v
MCP server (filesystem, GitHub, your own)
```

## See it in 30 seconds

```bash
brew install nocktechnologies/tap/nockguard      # or: go install github.com/nocktechnologies/nockguard/cmd/nockguard@latest

nockguard init                                   # writes ~/.nockguard/policy.yaml (default-deny starter; never clobbers an existing one)
nockguard proxy --upstream "npx -y @modelcontextprotocol/server-filesystem /path/to/project" --agent coder
```

Point your agent at `nockguard` instead of the server:

```json
{
  "mcpServers": {
    "files": {
      "command": "nockguard",
      "args": ["proxy", "--upstream", "npx -y @modelcontextprotocol/server-filesystem /path/to/project", "--agent", "coder"]
    }
  }
}
```

From here every `tools/call` flows through the policy engine and lands in the audit trail. Then:

```bash
nockguard verify --agent coder        # prove the trail is intact and authentic (exit 0), or tampered (exit 2)
nockguard policy propose --agent coder # turn what the agent actually used into a starter allowlist
nockguard selftest                     # prove the firewall really BLOCKS — a denied tool and a leaked secret, through the live gate
```

`selftest` is the one to run first if you only run one: it is proof-of-block, not a config check. A firewall that proves nothing does not pass.

### Observe first, then enforce

You do not have to write a policy up front. Run in `mode: allow` with the audit trail on, let the agent work, then `policy propose` gives you an allowlist made of the tools it really used, `policy shadow-report` shows what a stricter policy *would* have denied, and you flip to `mode: deny` when the shadow window is clean. The trail you built while observing is the same trail you audit later.

## Install

```bash
brew install nocktechnologies/tap/nockguard
```

Or build from source:

```bash
go install github.com/nocktechnologies/nockguard/cmd/nockguard@latest
```

## Writing a policy

`nockguard init` writes a commented, default-deny starter you edit in place. Or write one yourself — per-agent allow/deny with `*` wildcards, and a `default` for agents you did not name:

```yaml
# policy.yaml
agents:
  coder:
    allow:
      - "read_*"
      - "search_*"
      - "github_*"
    deny:
      - "github_delete_*"

  reviewer:
    allow:
      - "read_*"
      - "search_*"
    deny:
      - "write_*"

  default:
    mode: allow
    deny:
      - "deploy_*"
      - "*_delete_*"
```

```bash
nockguard proxy \
  --upstream "npx -y @modelcontextprotocol/server-filesystem /path/to/project" \
  --agent coder \
  --policy policy.yaml
```

`--upstream` and `--agent` are required; `--policy` defaults to `~/.nockguard/policy.yaml`. An agent with no policy and no `default` is **fail-closed**: every tool is denied and NockGuard says so loudly at startup.

## Policy rules

- **allow**: Tool patterns the agent can use. Supports `*` wildcards.
- **deny**: Tool patterns blocked regardless of allow rules. Deny takes precedence.
- **shadow**: Dry-run allowlist for observe-to-enforce staging. A tool outside
  `shadow` records `would-deny` in the audit trail but is not blocked.
- **ask**: Tool patterns that return the `Ask` verdict. NockGuard holds the call for a human approval decision before forwarding it. Denial or timeout drops the call.
- **fail_mode**: `deny` (default) rejects malformed or ambiguous `tools/call` messages that NockGuard cannot safely interpret; `ask` parks those failures behind approval instead.
- **mode**: `allow` (default) permits unlisted tools, `deny` blocks them.
- **default**: Fallback policy for agents not listed by name.
- **validate_input** (Phase 2): built-in input-validation categories applied to tool-call arguments — `sqli`, `path_traversal`, `secrets`. Opt-in per agent.
- **block_params** (Phase 2): custom regex patterns; a tool call is blocked if any argument matches.
- **rate_limit** (Phase 3): at most `max_calls` tool calls within a sliding `window` (a Go duration — `30s`, `1m`, `1h`). The allowance refills as the window slides — this bounds bursts and runaway tool-call loops without blocking normal traffic.
- **spend_cap** (Phase 3): a hard cumulative ceiling of `max_calls` tool calls for the whole proxy session. It never refills — once hit, every further call is blocked. This is the kill-before-runaway stop that bounds total cost for an agent left running unattended.
- **trust**: opt-in behavioral trust scoring. When `enabled: true`, NockGuard persists a per-agent score at `~/.nockguard/trust/<agent>.json` and scales the configured rate-limit cap from `0.1x` to `2.0x` based on recent allow/warn/deny outcomes. See `docs/TRUST.md`.

```yaml
agents:
  coder:
    allow: ["read_*", "search_*"]
    shadow: ["read_*", "search_*"]
    ask: ["deploy_*"]
    fail_mode: ask
    validate_input: ["sqli", "path_traversal", "secrets"]
    block_params:
      - "(?i)rm\\s+-rf\\s+/"
    rate_limit:
      max_calls: 60
      window: 1m
    trust:
      enabled: true
    spend_cap:
      max_calls: 5000
```

Policy verdict precedence is `deny` first, then `ask`, then normal allow/mode logic. An `Ask` verdict is not a warning or "flag but pass" result: the call is withheld until approval. Any state-write intents attached to the policy decision are also withheld; NockGuard applies them only after approval, and drops them on denial or timeout. The legacy `require_approval` key remains accepted for existing policies, but new policies should use `ask`.

Rate limiting and spend caps are opt-in and independent — set one, both, or neither. NockGuard sits at the MCP layer and sees tool *calls*, not upstream API token spend, so the spend cap is denominated in tool calls (a proxy for cost), enforced before the call reaches the server. When a call clears the allowlist and input validation but exceeds a limit, the agent receives a JSON-RPC error (`rate limit exceeded` / `spend cap exceeded`); policy-denied or input-blocked calls never consume budget. Ask calls are metered before the approval prompt, preserving the existing Phase 5 gate order.

## Verify a trail in one command

Any signed audit trail can be proven intact and non-repudiable **offline** — no daemon, no signing key, only the public key:

```bash
nockguard verify --agent coder    # one agent's trail (exit 0 = intact + authentic, 2 = tampered)
nockguard verify --all          # every per-agent trail in one shot — prove the whole fleet
```

`--all` scans the audit dir for every `<agent>.audit.jsonl`, verifies each with that agent's own public key, and prints a per-agent summary (exit 0 = all intact, 2 = any tampered, 1 = any it could not verify). That single command replays the whole hash chain and the per-entry signatures: it proves the trail was not edited, reordered, truncated, or signed by anyone but the holder of the agent's private key. `verify` is the first-class form of `audit verify` (below), which documents HMAC vs Ed25519 signing, per-agent keys, and the compliance evidence packs.

## Prove the firewall BLOCKS — `selftest`

`verify` proves the audit **trail** is intact. But a firewall can keep a flawless trail while silently forwarding every call — an intact record of an open door. `selftest` closes that gap: it proves the live **enforcement** path actually blocks.

```bash
nockguard selftest --policy policy.yaml    # exit 0 = enforcement PROVEN, 2 = a GAP, 1 = inconclusive
nockguard selftest --policy policy.yaml --json
```

It loads the active policy (a firewall whose own config will not load, or that governs no agents, is inconclusive — non-zero) and then runs two proof-of-block checks by driving **benign canary probes through the same proxy gate real agent traffic takes** — not a mock:

- **policy-deny** — a canary tool (`nockguard-selftest-probe`) the policy DENIES must be blocked at the gate. PASS = denied.
- **input-validation** — a tool argument carrying a **synthetic** secret-shaped string (no real credential) must be flagged by input validation. PASS = flagged.

Every check runs a **positive control** first: it proves the probe *would* be forwarded *without* the deny rule / validation, so a block is real — not a missing tool, an unwired probe, or a setup error. If the positive control fails, the check is `SKIP`, never `PASS`. A block that coincides with a genuine policy `Deny` decision is distinguished from an inconclusive error path. Exit is `0` only when at least one check PASSED and none FAILED — a firewall that proved nothing (all SKIP, or no active policy) does not pass. This is proof-of-block, deliberately distinct from `audit verify`'s proof-of-trail.

## Audit Trail (Phase 4)

NockGuard can write a structured, append-only record of every policy decision — turning the firewall from a gate into an accountable trail of what each agent attempted and what the policy did about it. Enable it with a top-level `audit` block:

```yaml
audit:
  enabled: true
  path: ~/.nockguard/logs/audit.jsonl   # optional; this is the default
agents:
  coder:
    allow: ["read_*", "search_*"]
```

Each decision is one JSON object per line (JSON Lines):

```json
{"ts":"2026-06-03T18:30:00Z","agent":"coder","tool":"github_delete_repo","decision":"deny","reason":"deny-rule \"github_delete_*\""}
{"ts":"2026-06-03T18:30:01Z","agent":"coder","tool":"read_file","decision":"allow","reason":"allow-rule \"read_*\""}
```

`decision` is one of `allow`, `deny`, `would-deny` (shadow dry-run miss), `block` (input validation), `ratelimit`, `approval-granted`, `approval-denied`, `state-write`, or `hide` (filtered from `tools/list`). Auditing is opt-in (absent or `enabled: false` keeps Phase 1–3 behavior) and fail-open — an audit write error is logged but never blocks or fails a tool call.

`reason` names the specific policy rule behind each decision — `deny-rule "…"`, `allow-rule "…"`, `no allow-rule matched`, `default-allow (no allow list)`, or `no policy for agent (fail-closed)` — so the trail is *explainable* rather than an opaque `policy`. The matched rule is recorded operator-side only; the error returned to the agent stays minimal (`denied by policy`), so a hostile agent cannot map the policy surface from rejections.

**By design, NockGuard does not write raw tool-call parameters to the audit trail.** Logging arguments would persist exactly the secrets and injection payloads that Phase 2 exists to keep out, so the trail records the *decision* (agent, tool, outcome, reason), not the payload.

### Forwarding to the NockCC ops-log

NockGuard can stream **enforcement decisions** (`deny`, `block`, `ratelimit`, `approval-granted`, `approval-denied`) to the [NockCC](https://cc.nocktechnologies.io) ops-log, so what the firewall blocks or parks across the fleet shows up in one Command Center feed. Allowed calls, state-write records, and tool-list hides are not forwarded — the centralized feed stays high-signal, while the local JSONL keeps the complete record.

```yaml
audit:
  enabled: true
  forward:
    enabled: true
    url: https://cc.nocktechnologies.io
    api_key_env: NOCKCC_API_KEY   # the key is read from this env var, never stored in the policy file
```

Forwarding is **asynchronous and fail-open**: events post on a background worker, `Enqueue` never blocks (it drops if the buffer saturates), and any HTTP/transport error is swallowed — a slow or unreachable NockCC can never stall or fail a tool call. Severity maps as `block → high` (an injection / secret-exfil attempt), `would-deny → info`, and `deny` / `ratelimit → warn`. Misconfiguration (forwarding enabled with no `url`, or an `api_key_env` that doesn't resolve) fails loud at startup rather than silently dropping every event.

## Observe to Enforce

Use the signed audit trail to derive enforcement from the tools an agent actually
used:

```bash
nockguard policy propose --agent coder
```

The command reads `~/.nockguard/logs/coder.audit.jsonl`, extracts distinct allowed
tools, and prints a proposed `shadow:` allowlist. After adding that block to the
agent policy, run in observe mode and preview false positives:

```bash
nockguard policy shadow-report --agent coder
```

`0 would-deny entries` means the shadow window is clean enough for human review
before flipping `mode: allow` to `mode: deny`.

### Tamper-evidence (HMAC hash-chain)

Audit entries can be signed with an HMAC hash-chain — each entry's signature covers its own content plus the previous entry's signature, so any insertion, deletion, or edit anywhere in the trail breaks the chain from that point forward. Signing is opt-in (provide a key); without one, the trail behaves exactly as the unsigned JSONL above. This closes Phase 4.

```bash
nockguard audit verify --key-env NOCKGUARD_AUDIT_KEY   # exit 0 = intact, 2 = tampered
```

### Non-repudiation (Ed25519)

HMAC is *tamper-evident* but symmetric: whoever verifies the trail holds the same key that produced the signatures, and could therefore forge them. **Ed25519** signing closes that gap — it is asymmetric. A private key signs; the trail is verified with the corresponding **public key**, which *cannot* produce signatures. So a passing verification is proof that the holder of the private key signed every entry — the verifier never has the power to forge one. That is the difference between "this trail wasn't edited" and "this trail is *non-repudiable*": court-credible, and aligned with the emerging [IETF agent-audit-trail](https://datatracker.ietf.org) direction (hash-chain + asymmetric signatures).

Generate a keypair, then point the policy at the private seed via an env var:

```bash
nockguard keygen
# NOCKGUARD_AUDIT_ED25519_KEY=<private seed — secret, never commit>
# NOCKGUARD_AUDIT_ED25519_PUB=<public key — share with verifiers>
```

```yaml
audit:
  enabled: true
  sign_ed25519_key_env: NOCKGUARD_AUDIT_ED25519_KEY   # hex 32-byte seed or 64-byte key; read from env, never stored in the policy file
```

`sign_ed25519_key_env` takes precedence over `sign_key_env` when both are set. Verify the trail with only the public key — the signer's secret is never needed to audit it:

```bash
nockguard audit verify --ed25519-pub-env NOCKGUARD_AUDIT_ED25519_PUB   # exit 0 = intact + authentic, 2 = tampered or wrong signer
```

## Live Wall

The audit trail is a file; the **Live Wall** makes it something you watch. `nockguard-wall` tails the audit JSONL and streams each policy decision to a local browser dashboard in real time, color-coded by outcome — every tool call an agent attempted and exactly what the firewall did about it. It is the visible layer over NockGuard's invisible enforcement: visceral proof of the accountability moat.

```bash
go run ./cmd/nockguard-wall                 # serves http://127.0.0.1:8787 (loopback = private)
go run ./cmd/nockguard-wall --demo          # synthesize a sample stream when there's no live traffic
go run ./cmd/nockguard-wall --audit <path>  # point at a specific audit JSONL
```

It binds to loopback by default (private), embeds its own page (single binary, no assets to ship), and replays the existing audit record on open so the wall is populated immediately, then streams new decisions as they land. The wall reads only the recorded decision (agent, tool, outcome, reason) — never raw tool-call parameters, consistent with the audit trail's no-payload rule.

## How It Works

NockGuard intercepts two MCP methods:

- **tools/list**: Filters the tool list response, hiding denied tools from the agent.
- **tools/call**: Checks the tool name against policy before forwarding. `Deny` rejects immediately. `Ask` holds the call for the configured approver and forwards only on approval, applying any withheld state writes after that approval. With Phase 2 validation enabled, NockGuard also scans the call's arguments (recursively, keys and values) against the configured rule categories and custom patterns, blocking injection attempts and outbound sensitive-data leaks. With Phase 3 limits enabled, a call that clears policy and validation is then metered against the agent's rate limit and spend cap. Denied, ask-denied, blocked, or over-limit calls get a JSON-RPC error response.

All other MCP traffic passes through unmodified. NockGuard is version-transparent — it works with any MCP protocol version. Input validation is opt-in: an allowlist-only policy behaves exactly as in Phase 1.

## Coverage scope

NockGuard operates at the **MCP transport layer**. It intercepts messages on the stdio pipe between the agent and an MCP server. That is its coverage boundary.

**What NockGuard covers:**
- Every `tools/list` and `tools/call` MCP message the agent sends through the proxy.
- All policy decisions (allow, deny, ask, rate-limit, spend-cap) on those calls.
- The full audit trail and Live Wall feed for those decisions.

**What NockGuard does not cover:**
- Direct HTTP/REST calls an agent makes to a backend service (e.g., a backend's REST API via `curl` or an HTTP client) that bypass the MCP proxy entirely.
- Network egress to arbitrary URLs — NockGuard is not an HTTP forward proxy.
- Calls routed to MCP servers that are not wired through NockGuard (an agent can have multiple MCP servers; only the ones using `nockguard proxy` as their command are gated).

This is a deliberate design constraint, not a defect. An agent that calls the backing REST API directly — rather than through its MCP server — operates outside the gated channel. The accountability guarantee is: **every MCP tool call through NockGuard is policy-checked, audited, and optionally non-repudiably signed**. It does not extend to direct HTTP traffic that never touches the proxy.

If your threat model includes agents switching to curl/HTTP as a bypass, enforce that at the network layer (egress firewall, outbound proxy, NockLock seccomp policy) rather than at the MCP layer. HTTP forward-proxy coverage for NockGuard is a planned feature.

## Relationship to NockLock

- **NockLock** = secret isolation ("Fence your environment")
- **NockGuard** = MCP firewall ("Guard your agent's tools")

Same brand, same tap, independent products. Use one or both.

## What is free, and what is a service

Everything in this repository is MIT and fully functional. There is no license key, no feature flag that phones home, and nothing in the binary that stops working after a date. The on-ramp — `proxy`, `verify` / `audit verify`, `policy propose` / `shadow-report`, `init`, `keygen`, `selftest`, and the Live Wall you run yourself with `go run ./cmd/nockguard-wall` — is the product, and it is yours.

What Nock Technologies sells is the part that only makes sense as a **service or at fleet scale**: a hosted Live Wall across many agents and machines, compliance evidence packs generated from your signed trails (`nockguard evidence` today; hosted generation and retention later), fleet-wide trust and egress enforcement, and support. If you never need those, you never need us — and your trail still verifies with the public key alone.

## Roadmap

- [x] Phase 1: Tool allowlists (per-agent, wildcard, default-deny)
- [x] Phase 2: Input validation (SQLi / path-traversal / secrets rule sets + custom regex on tool-call arguments)
- [x] Phase 3: Rate limiting and spend caps (per-agent sliding-window rate limit + hard cumulative session cap)
- [x] Phase 4: Audit trail — structured JSONL trail, NockCC ops-log forwarding, and tamper-evident HMAC hash-chain signing
- [x] Phase 4+: Non-repudiable audit — Ed25519 asymmetric signing (private-key signs, public-key verifies), `keygen`, standards-aligned
- [x] Phase 5: Interactive approval gates — human-in-the-loop hold on consequential tools (dedicated Telegram bot, fail-safe deny)
- [x] Live Wall: real-time local dashboard streaming every policy decision from the audit trail

## License

MIT
