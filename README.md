# NockGuard™

**The MCP firewall.** Put NockGuard in front of an MCP server and the tool calls routed through it are policy-checked. With auditing and Ed25519 signing enabled, decisions can be recorded in a verifiable trail. A private-key holder can sign new records, and detecting rollback of both the trail and its signed checkpoint requires an external anchor.

Every agent connector is untrusted until proven otherwise. NockGuard is how you prove it.

```
Agent (Claude Code, Codex, Cursor, any MCP client)
    |
    v
NockGuard  ── allow / deny / ask ──▶  optional signed audit trail  ──▶  `nockguard verify`
    |
    v
MCP server (filesystem, GitHub, your own)
```

## See it in 30 seconds

First [install NockGuard](#install), then run:

```bash
QS=$(mktemp -d)                                  # private fixture directory (not a predictable /tmp path)
printf 'NockGuard read succeeded\n' > "$QS/hello.txt"
echo "$QS"                                        # substitute this path for <QS> below
nockguard init                                   # writes ~/.nockguard/policy.yaml (coder policy, audit enabled; never clobbers an existing one)
nockguard keygen --agent coder                   # writes ~/.nockguard/keys/coder.ed25519 and coder.pub
```

The generated policy allows `coder` to call the filesystem server's `read_file` and `read_text_file` tools and denies `write_file`. Auditing is enabled, and the key generated above signs `coder`'s trail. Point your MCP client at NockGuard:

```json
{
  "mcpServers": {
    "files": {
      "command": "nockguard",
      "args": ["proxy", "--upstream", "npx -y @modelcontextprotocol/server-filesystem <QS>", "--agent", "coder"]
    }
  }
}
```

Ask your MCP client to call `read_file` with `{"path":"<QS>/hello.txt"}`: it should return `NockGuard read succeeded`. Each `tools/call` routed through this proxy is policy-checked; with auditing enabled and the per-agent key available, its decision is recorded in a signed audit trail. After the call, run:

```bash
nockguard verify --agent coder        # reads ~/.nockguard/keys/coder.pub; exit 0 and PROTECTED for the signed trail
nockguard wall --agent coder          # open the Live Wall for coder's signed trail
```

To exercise the blocked canary as well, run `python3 scripts/quickstart-acceptance.py` from a source checkout. This Linux CI test runs the commands above in an empty home with a local MCP stub using the filesystem server's tool names. It confirms both reads succeed, a direct `write_file` call is denied without creating a file, `verify` exits 0 with `PROTECTED`, and the signed trail records both allow and deny decisions. Denied tools are hidden from normal MCP tool discovery, so the test sends the canary call directly.

### Observe first, then enforce

You do not have to write a policy up front. Run in `mode: allow` with the audit trail on, let the agent work, then `policy propose` gives you an allowlist made of the tools it really used, `policy shadow-report` shows what a stricter policy *would* have denied, and you flip to `mode: deny` when the shadow window is clean. The trail you built while observing is the same trail you audit later.

## Install

On macOS, Homebrew installs both `nockguard` and `nockguard-wall` from the
current release:

```bash
brew install nocktechnologies/tap/nockguard
```

On Linux, download the [latest release](https://github.com/nocktechnologies/nockguard/releases/latest)
archive for your architecture into an empty directory, and download `SHA256SUMS`
from the same release. Run these commands there, and continue only if the check
prints `OK` for your archive:

```bash
sha256sum --check --ignore-missing SHA256SUMS \
  && tar -xzf nockguard_*_linux_*.tar.gz \
  && sudo install -m 0755 nockguard nockguard-wall /usr/local/bin/
```

Run `nockguard wall` to start the Live Wall.

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
- **ask**: Tool patterns that return the `Ask` verdict. Ask tools remain visible in `tools/list`; NockGuard holds each call for a human approval decision before forwarding it. Denial or timeout drops the call.
- **fail_mode**: `deny` (default) rejects malformed or ambiguous `tools/call` messages that NockGuard cannot safely interpret; `ask` parks those failures behind approval instead.
- **mode**: Explicit `allow` permits unlisted tools when there is no allow list;
  `deny` blocks them. With no allow list or explicit mode, the policy denies
  by default. With an allow list, unmatched tools are denied.
- **default**: Fallback policy for agents not listed by name.
- **validate_input** (Phase 2): built-in input-validation categories applied to tool-call arguments — `sqli`, `path_traversal`, `secrets`. Opt-in per agent.
- **block_params** (Phase 2): custom regex patterns; a tool call is blocked if any argument matches.
- **rate_limit** (Phase 3): at most `max_calls` tool calls within a sliding `window` (a positive Go duration — `30s`, `1m`, `1h`). Missing, invalid, zero, and negative windows are rejected when loading the policy. The allowance refills as the window slides — this bounds bursts and runaway tool-call loops without blocking normal traffic.
- **spend_cap** (Phase 3): a hard cumulative ceiling of `max_calls` tool calls for the whole proxy session. It never refills — once hit, every further call is blocked. This is the kill-before-runaway stop that bounds total cost for an agent left running unattended.
- **trust**: opt-in behavioral trust scoring. When `enabled: true`, NockGuard persists a per-agent score at `~/.nockguard/trust/<agent>.json` and scales the configured rate-limit cap from `0.1x` to `2.0x` based on recent allow/warn/deny outcomes. See `docs/TRUST.md`.
- **inject** (Phase 6): credential injection at the proxy seam, so a secret a tool needs never enters the agent's context. Rules name tool globs, secret references (`env:NAME`, `file:/abs/path`, or `nockcc:NAME`), and the JSON argument path where the credential is injected (under params.arguments, overwriting whatever the agent sent). A `nockcc:` reference reads the NockCC credential vault at forward time using the proxy's own `NOCKCC_BASE_URL` and `NOCKGUARD_VAULT_AGENT_TOKEN` (sent as `X-Agent-Token`); both are stripped from the upstream child environment. The vault key name is operator-only and appears in policy and operator-side logs/audit, never in agent-facing errors. Optional template wraps the resolved value (e.g. Bearer {secret}). Resolution happens at forward time (not load), so credential rotation works without restart. Injection is `tools/call` only and happens only on allowed calls after input validation, before the upstream forward. Fail-closed: unresolvable refs (env unset, file missing/unreadable, vault unavailable, unknown scheme, value < 8 bytes) or unsettable arg paths (params.arguments not an object or intermediate path not an object) reject the call. File-scheme secrets are read from regular files with mode no more permissive than 0600, owned by the proxy uid or 0, and opened with O_NOFOLLOW (symlinks rejected outright). Any injected value is scrubbed (plaintext, JSON-escaped, URL-escaped, base64 std/URL variants, padded/unpadded) from agent-facing output using the fixed marker `[nockguard:redacted]`, preventing leakage in error responses. Two rules that write the same argument must name their tools literally, or one literal plus a glob that does not match it. Two globs writing the same argument are rejected at load, even when they look disjoint; split them into literal tool names. One warning is issued at load time per tool glob appearing in multiple inject rules. Limitation: injection protects the credential from the agent, not the tool; the tool receives the plaintext. Keep globs narrow (one tool per rule recommended) and pair with deny rules on sibling tools that could exfiltrate. This is a v1 boundary.

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

Policy verdict precedence is `deny` first, then `ask`, then normal allow/mode logic. An `Ask` verdict is not a warning or "flag but pass" result: the call is withheld until approval. Any state-write intents attached to the policy decision are also withheld; NockGuard applies them only after approval, and drops them on denial or timeout. The legacy `require_approval` key remains accepted for existing policies, but new policies should use `ask`. An `ask` call needs an approver: the dedicated Telegram bot, or the network-free local approver (`NOCKGUARD_APPROVER=local`, see "Local approver" under Phase 5 below). With neither, every `ask` call is denied.

Rate limiting and spend caps are opt-in and independent — set one, both, or neither. NockGuard sits at the MCP layer and sees tool *calls*, not upstream API token spend, so the spend cap is denominated in tool calls (a proxy for cost), enforced before the call reaches the server. When a call clears the allowlist and input validation but exceeds a limit, the agent receives a JSON-RPC error (`rate limit exceeded` / `spend cap exceeded`); policy-denied or input-blocked calls never consume budget. Ask calls are metered before the approval prompt, preserving the existing Phase 5 gate order.

## Verify a trail in one command

An Ed25519-signed audit trail can be checked for signature and hash-chain integrity **offline** with only the public key:

```bash
nockguard verify --agent coder    # one agent's trail (exit 0 = verified, 2 = read or integrity failure)
nockguard verify --all          # check every per-agent trail found in the audit directory
```

`--all` scans the audit dir for every `<agent>.audit.jsonl`, verifies each with that agent's own public key, and prints a per-agent summary (exit 0 = all intact, 2 = any tampered, 1 = any it could not verify). An audit dir with **zero** trails is not "protected": there is nothing to verify, so `--all` prints `VERDICT: NO_TRAILS` and exits 1. That command replays the hash chain and signatures, detecting edits, reordering, and truncation against the retained signed checkpoint. It cannot distinguish the original writer from another holder of the private key or detect rollback of both trail and checkpoint without an external anchor. `verify` is the first-class form of `audit verify` (below), which documents HMAC vs Ed25519 signing, per-agent keys, and the compliance evidence packs.

### One verdict for a session across NockGuard and NockLock

When an agent runs under `nocklock wrap`, NockLock records the session in its own signed SQLite log and NockGuard stamps the same `session_id` (and its signing key's `key_id`) on every trail line. `verify --session` checks both chains for that session and gives one verdict:

```bash
nockguard verify --session <id> \
  --lock-db <path/to/nocklock/events.db> \
  --guard-trail <path/to/agent.audit.jsonl> \
  --lock-pub-env NOCKLOCK_PUB --guard-pub-env NOCKGUARD_PUB    # or --pub-env <ENV> when one key signs both
```

- Paths are explicit. There is no discovery, and a missing flag, an unset key variable, or an unreadable file is a failure (exit 1), never a pass.
- The NockLock side runs nocklock's own public verifier (`pkg/receipt`): every row's hash link, the session rows' signatures, and the signed chain head, which must anchor exactly the chain on disk.
- The NockGuard side verifies the **whole** trail with the same Ed25519 verifier as `verify`, including the signed `.hwm` truncation check, then selects the lines whose `session_id` matches. A line whose `key_id` names a different key than the one supplied is `TAMPERED`.
- `PROTECTED` (exit 0) needs both chains intact, at least one row for the session in each, and both tails verified. The NockGuard tail counts as verified only when the signed `.hwm` checkpoint covers **every** entry in the trail; entries past it (a writer mid-append, or a crash before the checkpoint update) make the Guard side `UNANCHORED`, so re-run once the writer is idle. Otherwise the verdict is the worst of the two: `TAMPERED` (exit 2) > `UNVERIFIABLE` > `UNSIGNED` > `NO_ROWS` > `UNANCHORED` (all exit 1).
- Both key fingerprints (`hex(sha256(pub))`) are printed; `--json` gives the verdict plus per-chain detail.
- Not covered: rolling a whole chain back **together with** its signed head (chain_head or `.hwm`) to an earlier genuine state passes every local check. Only `nocklock verify --against-remote-anchor` detects that, and only for the NockLock chain.

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

`decision` is one of `allow`, `deny`, `would-deny` (shadow dry-run miss), `block` (input validation), `ratelimit`, `approval-granted`, `approval-denied`, `state-write`, `hide` (filtered from `tools/list`), or `dispatch` (required-audit permission to forward).

When auditing is enabled, `proxy`, `mcp-http`, and `mcp-listen` persist a decision
before forwarding a tool call. A pre-forward write failure refuses that call;
a required-writer failure refuses later calls until repair and reopen. `proxy`
and `mcp-listen` write a
`dispatch` row durably before forwarding. Deferred decisions are written in
request order, so a response that arrives ahead of an earlier pending call can
be released before its decision row is written. If that later write fails, the
writer latch refuses every later call and status reports the failure. `mcp-http`
writes its observe decision before forwarding. Use
`--audit-best-effort` on one of these local commands only if you explicitly
want the old behavior; startup prints a warning. `nockguard status --agent <name>`
(or `doctor`) and the Live Wall show `last required audit write failed`
when a required write fails. The status command accepts `--audit <path>` for
custom trail paths. `mcp-gateway` requires auditing and also blocks later
requests across its sessions until storage is repaired and the process restarted.
If a failure happens after forwarding, the response warns that the tool may have
executed and must not be retried automatically. A dispatch row is not proof of
execution or success. See the [gateway recovery contract](docs/design/hosted-gateway.md).

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

Use the audit trail to derive enforcement from the tools an agent actually
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

Zero-config observe persists its per-agent signing seed at
`~/.nockguard/keys/<agent>.ed25519`; it refuses symbolic links in the
`~/.nockguard` state path, key directory, or seed file.

### Tamper-evidence (HMAC hash-chain)

Audit entries can be signed with an HMAC hash-chain — each entry's signature covers its own content plus the previous entry's signature, so changes within the retained trail break the chain. A holder of the HMAC key can sign a replacement chain, and rolling back both trail and checkpoint requires an external anchor to detect. Signing is opt-in (provide a key); without one, the trail behaves exactly as the unsigned JSONL above. This closes Phase 4.

```bash
nockguard audit verify --key-env NOCKGUARD_AUDIT_KEY   # exit 0 = intact, 2 = tampered
```

### Public-key signing (Ed25519)

HMAC is symmetric: whoever verifies the trail holds the same key that signs it. With **Ed25519**, a private key signs and the corresponding **public key** verifies; a public-key holder cannot sign new records. A passing check shows that the retained entries and checkpoint match signatures made with the private key. It cannot identify which private-key holder wrote them, and a holder can sign a replacement trail and checkpoint. Detecting rollback of both requires an external anchor.

**Key files.** `nockguard keygen --agent <name>` writes the keypair instead of printing it, so the private seed never lands in terminal scrollback, shell history or an agent transcript:

| File | Contents | Mode |
|---|---|---|
| `~/.nockguard/keys/<name>.ed25519` | private seed, hex | `0600` (directory `0700`) |
| `~/.nockguard/keys/<name>.pub` | public key, hex | `0644` |

`keygen` prints only the two paths and the public key. It refuses to overwrite existing files without `--force` (a forced replacement means trails signed by the old key stop verifying), and refuses a symlink at either file or at the `keys` directory. `--print-env` restores the old behavior (prints `NOCKGUARD_AGENT_<NAME>_ED25519_KEY=` / `_PUB=` lines to stdout, writes no files) and warns that the seed is now in your terminal output; avoid it outside throwaway setups.

With `--agent <name>` these files are found by name; an env var always wins when set:

- **Signing** (`proxy`, `mcp-listen`, `egress-proxy`, `mcp-gateway`): `NOCKGUARD_AGENT_<NAME>_ED25519_KEY`, else the policy's own `audit.sign_ed25519_key_env` / `audit.sign_key_env` if it names one (so a seed file left by an earlier zero-config observe run never overrides what the policy says), else `~/.nockguard/keys/<name>.ed25519`. The seed file is refused unless it is a regular file owned by you with no group/other permission bits; an unsafe, unreadable or empty file is an error, not a silent fallback to unsigned or HMAC audit. A missing file, or a home directory that cannot be resolved, just means no key file and signing falls back exactly as it did before key files existed.
- **Verifying** (`verify --agent`, `verify --all`, `verify --export`, `evidence --agent`): `NOCKGUARD_AGENT_<NAME>_ED25519_PUB`, else `~/.nockguard/keys/<name>.pub`. Explicit `--ed25519-pub-env` / `--key-env` flags are unchanged. `verify` prints which public key it used (the env var name or the `.pub` path); `--json` carries it as `public_key_source`. An empty `.pub` is an error.

`keygen` and zero-config observe serialize on a per-agent lock (`~/.nockguard/keys/<name>.lock`, `0600`), so two concurrent `keygen --force` runs can never leave a `.pub` that does not match the seed; observe repairs a `.pub` that no longer matches. Existing env-based deployments need no change. One tradeoff to know: an env-var seed is stripped from the upstream MCP server's environment, but a key file is readable by anything running as the same user, including that upstream. If the upstream is untrusted, run the proxy as a separate user, or keep using the env var.

The agent-less `nockguard keygen` is the `default` identity (`default.ed25519` / `default.pub`), the same one zero-config observe mode creates, so the two share a key. The policy-wide `sign_ed25519_key_env` setting still reads an env var; fill it from the file without printing it:

```bash
nockguard keygen     # no --agent = the "default" identity: ~/.nockguard/keys/default.ed25519 (seed, 0600) + default.pub
export NOCKGUARD_AUDIT_ED25519_KEY="$(cat ~/.nockguard/keys/default.ed25519)"   # the seed goes file -> env, never through your terminal output
export NOCKGUARD_AUDIT_ED25519_PUB="$(cat ~/.nockguard/keys/default.pub)"
```

```yaml
audit:
  enabled: true
  sign_ed25519_key_env: NOCKGUARD_AUDIT_ED25519_KEY   # hex 32-byte seed or 64-byte key; read from env, never stored in the policy file
```

`sign_ed25519_key_env` takes precedence over `sign_key_env` when both are set. Verify the trail with only the public key — the signer's secret is never needed to audit it:

```bash
nockguard audit verify --ed25519-pub-env NOCKGUARD_AUDIT_ED25519_PUB   # exit 0 = signatures and retained chain check out, 2 = tampered or wrong key
```

### Auditable References (observe mode)

When your policy allows `nockcc_nock_*` tool calls, NockGuard extracts the NockCC card ID from each call and records it in the audit trail. This links a policy decision to the card ID named by the call. With signing enabled, the extracted reference is covered by the signature; it does not prove that the upstream action succeeded.

Each audit entry can carry these extracted fields:

- **nock_id** — The NockCC card ID (extracted from `nockcc_nock_claim`, `nockcc_nock_update`, `nockcc_nock_get`, `nockcc_nock_release` calls).
- **pr** — Reserved for GitHub PR references (not yet extracted).
- **review_id** — Reserved for NockCC review IDs (not yet extracted).
- **parent_audit_seq** — Reserved for audit sequence links (not yet extracted).

For example, a sequence of tool calls:

```json
{"ts":"2026-06-03T18:30:00Z","agent":"kit","tool":"nockcc_nock_claim","decision":"allow","nock_id":12345,"sig":"abc123..."}
{"ts":"2026-06-03T18:30:01Z","agent":"kit","tool":"nockcc_nock_update","decision":"allow","nock_id":12345,"sig":"def456..."}
{"ts":"2026-06-03T18:30:02Z","agent":"kit","tool":"nockcc_nock_release","decision":"allow","nock_id":12345,"sig":"ghi789..."}
```

All three rows carry `nock_id:12345`, extracted from each call. When signing is enabled, the signature chain includes the nock_id field, so verification detects alteration of a recorded card reference against the retained checkpoint.

Extraction is conservative: only known tools and typed parameter patterns are recognized. Unknown tools, missing parameters, or malformed arguments yield no extracted field for that row. The feature never guesses. This keeps the audit trail faithful to what actually happened.

## Live Wall

The audit trail is a file; the **Live Wall** makes it something you watch. `nockguard-wall` tails the audit JSONL and streams recorded policy decisions to a local browser dashboard in real time, color-coded by outcome. Auditing must be enabled for decisions to appear.

The Wall leads with its configured Guard trail and optional Lock DB, agent and recent session, verification status and last check time, and export scope. Its badges and browser pulse count the same filtered view of the newest 500 decisions; `/pulse` uses that same 500-row window. `allow`, `would-deny`, `observe`, `dispatch`, `state-write`, `approval-granted`, and the empty decision are routine: they count as approved and have no threat tier. Only `deny`, `block`, `ratelimit`, and `approval-denied` count as rejected; `ratelimit` also counts under `rateLimited`. `hide` (a `tools/list` filter) counts under `hidden` and has no threat tier. Any other decision counts under `other`, retains its raw name in the stream and decision filter, and receives a high threat tier without entering the rejected-share numerator or denominator. An empty or unreadable source is not presented as proof of zero violations; the empty view shows commands for generating sample or real audited traffic.

```bash
nockguard wall                              # serves http://127.0.0.1:8787 (loopback = private)
nockguard wall --agent coder                # watch this agent's signed audit trail
nockguard wall --demo                       # synthesize a sample stream when there's no live traffic
nockguard wall --audit <path>               # point at a specific audit JSONL
```

`nockguard wall` starts the companion `nockguard-wall` binary and passes its flags through, including `--verify-ed25519-pub-env`, `--verify-key-env`, and the opt-in `--proof-signing-key-env`. The wall reports the public-key source from `/verify`; `PROTECTED` requires a non-empty trail whose signed checkpoint covers every entry. Empty trails report `NO_ROWS`, and signed entries beyond the checkpoint report `UNANCHORED`. Receipt signing still requires the separate private-key flag.

The Wall binds to loopback by default (private), embeds its own page (no assets to ship), and replays the existing audit record on open so it is populated immediately, then streams new decisions as they land. It reads only the recorded decision (agent, tool, outcome, reason) — never raw tool-call parameters, consistent with the audit trail's no-payload rule.

With `--agent`, the wall reads `~/.nockguard/logs/<agent>.audit.jsonl` and resolves the public key from `NOCKGUARD_AGENT_<AGENT>_ED25519_PUB`, then `~/.nockguard/keys/<agent>.pub`. Explicit `--audit` and `--verify-ed25519-pub-env` values take precedence. Without a verification key, the Wall displays unverified records.

For an Ed25519-signed incident window, start the Wall with
`--proof-signing-key-env <ENV>` pointing at the trail's private key, click
**PROOF**, and hand the
downloaded file plus the public key to a reviewer. They can run
`nockguard verify --export <file> --ed25519-pub-env <ENV>` without the source trail. See
[verifying a Live Wall export](docs/verifying-the-trail.md) for the proof scope
and the explicit completeness limit on severity, decision, and text filters.

### NockLock + NockGuard in one wall

`--lock-db <path>` adds a [NockLock](https://github.com/nocktechnologies/nocklock) SQLite `events.db` beside NockGuard's JSONL trail in one Wall view; the sources retain their separate formats. The path is explicit (no discovery) and is opened read-only (`mode=ro`, `query_only`; never `immutable`, so rows NockLock appends show up live). The wall shows the six fence events — file, network and secret, blocked and passed — labeled `LOCK`, next to `GUARD` decisions and colored by outcome. Lifecycle and fence-status rows are skipped. Like Guard rows, a Lock row is the decision only: the event type and the target NockLock recorded (a path, a host, a secret *name*), never a request body or a secret value.

Each recent session also gets one signed-proof badge, computed by the same code as `nockguard verify --session` (NockLock's public `pkg/receipt` for the Lock chain, `audit.VerifyEd25519Bytes` for the Guard trail): `PROTECTED`, `TAMPERED`, `UNSIGNED`, `UNVERIFIABLE`, `NO_ROWS` or `UNANCHORED`, with both key fingerprints. Only `PROTECTED` is green. A missing or unusable key on either side is `UNVERIFIABLE`, never green. The wall builds ONE snapshot per refresh and renders every view from it: the Guard trail and its checkpoint are read once and verified once; the Lock DB is copied once with SQLite `VACUUM INTO` (one read transaction; that connection is `mode=ro` but not `query_only`, which would forbid the copy, and the copy lives in a private temp directory removed after the run) and both the Lock rows and the Lock chain walk use that copy. The badges, the replayed stream, `/pulse` and `/export` (signed or unsigned) read the same slices, so what the wall shows is what was checked. A refresh is not repeated within 4 s, and after that only when a log's size or mtime moved; because those can be preserved by an attacker, a refresh is also forced every 60 s. A Lock log above 100,000 events is not copied or verified: its badges read `UNVERIFIABLE` (too large to verify) and its rows are shown unverified. A Lock row that cannot be read is shown as `UNPARSEABLE` (within the 500-row window) and makes its session `UNVERIFIABLE`; the rest of the batch is unaffected, and the chain walk itself rejects an unreadable row anywhere in the log. A browser reconnect and an export always build a fresh snapshot; `/pulse` and `/sessions` reuse the last one. Reasons name the live Lock DB, never the temporary copy. The Lock DB path must be a regular file, not a symlink. Keys come from the environment, never the browser.

The header counts audit records, not calls: one allowed call writes a `dispatch` and an `allow` record. `tools/list` hides are counted apart as hidden tools and are not rejections or threats. The header counts readable decisions and unreadable rows separately. An unreadable row has no threat tier and leaves the rejected share unknown, while readable rejections remain visible.

```bash
# NockLock session + NockGuard agent "coder": Lock key and Guard key in env vars
export NOCKLOCK_AUDIT_ED25519_PUB=<lock public key hex>
export NOCKGUARD_AGENT_CODER_ED25519_PUB=<guard public key hex>
go run ./cmd/nockguard-wall --agent coder --lock-db ~/path/to/nocklock/events.db
# explicit form
go run ./cmd/nockguard-wall --audit ~/.nockguard/logs/coder.audit.jsonl \
  --verify-ed25519-pub-env GUARD_PUB --lock-db ./events.db --lock-pub-env LOCK_PUB
```

The badge is the rollback-blind local check `verify --session` makes (it consults no remote anchor); see its printed note.

`--lock-db` shows every session in the log, even with `--agent`; sessions the watched agent never touched badge `NO_ROWS`. Only the 10 most recent sessions get a badge (each badge is a full walk of both chains); export rows from older sessions read `unsigned`, meaning not checked. `--demo` cannot be combined with `--lock-db`.

With `--lock-db`, the `/export` CSV and JSON include every Guard row in the window plus the Lock rows (each source keeps its own 500-row cap). A Lock row reads `verified` only when its session is `PROTECTED` in that same snapshot, `failed` when `TAMPERED`, else `unsigned`. The response header `X-NockGuard-Lock-Verification` is `ok`, `unsigned` when no Guard verification key is configured (nothing is verified), or `unavailable` when the Lock DB could not be snapshotted (then no Lock rows are exported). The PROOF export is NockGuard rows only.

**Proof export scope.** The PROOF button is a signed export of the **NockGuard rows only**; it does not include Lock rows. Verify the Lock side with the session badge or `nockguard verify --session <id> --lock-db <path> --guard-trail <path> ...`. `/pulse` and the CSV/JSON export do include Lock rows (new trailing `source` column; a Lock row reads `verified` only when its whole session badge is `PROTECTED`). `--demo` shows a prominent **DEMO DATA** banner, synthetic Lock rows, and one `UNSIGNED` demo session badge. Demo rows are retained for replay and `/pulse`, but evidence exports are disabled because demo data is never verified.

## How It Works

NockGuard intercepts two MCP methods:

- **tools/list**: Keeps allowed and ask-verdict tools visible and hides denied tools. An ask tool is held for approval when called.
- **tools/call**: Checks the tool name against policy before forwarding. `Deny` rejects immediately. `Ask` holds the call for the configured approver and forwards only on approval, applying any withheld state writes after that approval. With Phase 2 validation enabled, NockGuard also scans the call's arguments (recursively, keys and values) against the configured rule categories and custom patterns, blocking injection attempts and outbound sensitive-data leaks. With Phase 3 limits enabled, a call that clears policy and validation is then metered against the agent's rate limit and spend cap. Denied, ask-denied, blocked, or over-limit calls get a JSON-RPC error response.

All other MCP traffic passes through unmodified. NockGuard is version-transparent — it works with any MCP protocol version. Input validation is opt-in: an allowlist-only policy behaves exactly as in Phase 1.

## Coverage scope

For hosted HTTP MCP clients, `nockguard mcp-gateway --config <path>` provides a
single-agent OAuth resource gateway behind a co-located HTTPS ingress. It checks
tokens through authenticated introspection, isolates session state, shares agent
quotas, and sends a separate service credential upstream. It requires enabled
auditing and a per-agent Ed25519 signing key. See the
[gateway contract and deployment steps](docs/design/hosted-gateway.md) and
[configuration template](docs/gateway.example.yaml). The issuer and ingress must
be supplied separately; this command does not deploy or switch a live connector.

NockGuard gates MCP messages through its stdio proxy or HTTP enforcement listeners.
Its separate `egress-proxy` covers HTTP/HTTPS clients that use the forward proxy.

**What NockGuard covers:**
- Every `tools/list` and `tools/call` MCP message the agent sends through the proxy.
- All policy decisions (allow, deny, ask, rate-limit, spend-cap) on those calls.
- An audit trail and Live Wall feed for those decisions when auditing is enabled.
- Destination-host decisions for HTTP/HTTPS traffic sent through `egress-proxy` (`--enforce` blocks denied hosts).

**What NockGuard does not cover:**
- HTTP/HTTPS traffic that does not use `nockguard egress-proxy`.
- Calls routed to MCP servers that are not wired through NockGuard (an agent can have multiple MCP servers; only the ones using `nockguard proxy` as their command are gated).

MCP policy enforcement applies to calls routed through NockGuard; direct HTTP calls require separate egress-proxy routing to be seen or enforced.

For HTTP/HTTPS clients configured to use it, `nockguard egress-proxy` checks destination hosts, records decisions when auditing is enabled, and can block denied hosts with `--enforce`; without that flag it is observe-only. Clients that bypass the proxy need a network-layer control such as an egress firewall or NockLock network fence.

## Relationship to NockLock

- **NockLock** = secret isolation ("Fence your environment")
- **NockGuard** = MCP firewall ("Guard your agent's tools")

Same brand, same tap, independent products. Use one or both.

## What is free, and what is a service

Everything in this repository is MIT-licensed. `nockguard-pool` is a scaffold: `validate` works, but `serve` refuses to start because routing is not implemented. There is no license key, no feature flag that phones home, and nothing in the binary that stops working after a date. The on-ramp — `proxy`, `verify` / `audit verify`, `policy propose` / `shadow-report`, `init`, `keygen`, `selftest`, and the Live Wall you run yourself with `nockguard wall` — is the product, and it is yours.

What Nock Technologies sells is the part that only makes sense as a **service or at fleet scale**: a hosted Live Wall across many agents and machines, hosted generation and retention of compliance evidence packs (`nockguard evidence` runs locally today), fleet-wide trust services, and support. Local Ed25519-signed trails can be checked with the public key alone, subject to the key-holder and rollback limits above.

## Roadmap

- [x] Phase 1: Tool allowlists (per-agent, wildcard, default-deny)
- [x] Phase 2: Input validation (SQLi / path-traversal / secrets rule sets + custom regex on tool-call arguments)
- [x] Phase 3: Rate limiting and spend caps (per-agent sliding-window rate limit + hard cumulative session cap)
- [x] Phase 4: Audit trail — structured JSONL trail, NockCC ops-log forwarding, and tamper-evident HMAC hash-chain signing
- [x] Phase 4+: Ed25519 audit signing (private-key signs, public-key verifies; key-holder and rollback limits above), `keygen`
- [x] Phase 5: Interactive approval gates — human-in-the-loop hold on consequential tools (dedicated Telegram bot or local socket approver, fail-safe deny)

  **Local approver** (no network). Start the proxy with `NOCKGUARD_APPROVER=local` and held calls wait on a unix socket at `~/.nockguard/approvals/<proxy pid>-<16 random hex>.sock` (directory `0700`, socket `0600`, both owned by the proxy's uid). On a single-user machine, if the home path is too long for a Unix socket, NockGuard uses `/tmp/nockguard-<uid>/approvals`; if another local account creates that path first, the approver refuses to start and `ask` decisions are denied. Generated socket paths are limited to 100 bytes; a system temp cleaner can remove a `/tmp` fallback while the proxy is running, causing later `ask` calls to time out and be denied until restart. The proxy and `nockguard approvals` must see the same `/tmp`, which is not true inside a private-tmp sandbox. The proxy refuses to start the approver — so every `ask` fails closed — if the parent or directory is a symlink, the socket is a symlink, is owned by someone else, or has any other mode. Decide from another terminal:

  ```
  nockguard approvals list            # id, agent, tool, reason, age — never arguments
  nockguard approvals approve <id>
  nockguard approvals deny <id>
  nockguard approvals prune           # remove dead sockets of crashed proxies (run with no proxies running)
  ```

  A proxy removes only its own socket, on a clean exit; the CLI skips sockets nobody answers on, and only the explicit `approvals prune` command removes sockets. A crashed proxy leaves a harmless dead socket behind; `approvals prune` removes only sockets owned by your uid that refuse two connections 1 s apart (run it when no proxies are running: on macOS a full listen backlog also looks like a refusal). Live sockets, non-sockets and other users' files are left alone.

  The timeout (2 minutes) and deny-on-timeout are unchanged. The decision is audited as `approval-granted` / `approval-denied` with the reason `approved by local:<uid>` / `denied by local:<uid>` (the uid is read from the socket peer, Linux and macOS only; elsewhere the approver does not start).

  **Trust boundary.** The socket is protected by file permissions and a same-uid peer check, nothing else. If the agent runs as the same user as the operator, it can open the socket and approve its own calls: this approver does not stop it on its own. To make the boundary real, run the agent under a different uid, or fence `~/.nockguard` away from it (for example with NockLock's filesystem fence). `NOCKGUARD_APPROVER` is stripped from the upstream MCP child's environment, but that is not a defense against a hostile same-uid agent.
- [x] Live Wall: real-time local dashboard streaming recorded policy decisions when auditing is enabled

## License

MIT
