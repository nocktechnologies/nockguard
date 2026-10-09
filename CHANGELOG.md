# Changelog

All notable changes to NockGuard are documented here.

## [Unreleased]

### Changed
- `nockguard keygen` now writes the keypair to `~/.nockguard/keys/<name>.ed25519` (seed, `0600`, directory `0700`) and `<name>.pub` (`0644`) and prints only the paths and the public key, so the private seed no longer lands in terminal scrollback, shell logs or agent transcripts. It refuses to overwrite without `--force` and refuses symlinks. Without `--agent` the name is `default`. The old stdout env lines (including the secret seed) are behind `--print-env`, which writes no files and warns on stderr. Scripts that parsed keygen's stdout must add `--print-env`. Unknown keygen flags are now an error; `--agent=<name>` is accepted.
- Zero-config observe mode now writes its public key to `<agent>.pub` (was `<agent>.ed25519.pub`).

- `verify` text output now names the public key source: a `public key: <env var or .pub path>` line before `VERDICT:` and a `(public key: ...)` suffix on each `verify --all` `[OK]` line. Parse `--json` (`public_key_source`) rather than the text.

### Added
- `verify --agent`, `verify --all`, `verify --export` and `evidence --agent` read `~/.nockguard/keys/<name>.pub` when `NOCKGUARD_AGENT_<NAME>_ED25519_PUB` is unset.
- Per-agent signing (`proxy`, `mcp-listen`, `egress-proxy`, `mcp-gateway`) reads `~/.nockguard/keys/<name>.ed25519` when `NOCKGUARD_AGENT_<NAME>_ED25519_KEY` is unset, refusing a seed file that is not a regular file owned by the current user with no group/other permission bits. The env vars still win when set. Audit format and signatures are unchanged.
- `keygen` and observe mode take a per-agent `flock` (`~/.nockguard/keys/<name>.lock`) across the seed and `.pub` publication, observe repairs a `.pub` that does not match its seed, and `verify` reports which public key source it used (`public_key_source` in `--json`).

### Fixed
- An empty or whitespace-only key file is now an error naming the path instead of reading as "no key" and silently weakening signing; a FIFO at a key path is refused instead of hanging the open; an unresolvable home directory no longer fails startup when no key file is wanted; an explicit `audit.sign_ed25519_key_env` / `sign_key_env` now outranks a key file for the same agent.

## [0.4.0] - 2026-10-09

### Added
- Offline proof for Live Wall incident exports. Start the Wall with `--proof-signing-key-env <ENV>` and it offers a PROOF download for an Ed25519 trail. The Wall verifies the checkpointed trail, selects the requested rows, and signs a receipt that binds the filters, row indexes, the chain links before each row, and the signed head. No private key is loaded unless the flag is given.
- `nockguard verify --export <file>` checks a proof file with the public key alone: the receipt signature, every row's signature, and, for a time-range export, that no row inside the window is missing. Severity, decision and text filtered exports verify row integrity only and say "not a complete window". A requested end time later than the capture time is clamped to the last fully elapsed second before capture, and the verifier rejects a receipt whose upper bound is past that limit. See `docs/verifying-the-trail.md`.
- `examples/exfil-demo/`: a self-contained poisoned MCP server demo. `bash examples/exfil-demo/run.sh` shows an agent told to read and email a fake SSH key, the starter policy blocking it, and `nockguard verify` on the resulting trail. `--unprotected` runs the same scenario without the policy.

### Fixed
- `--help` and `-h` now print usage and exit 0 for every subcommand, before any subcommand runs. Before this, `nockguard init --help` ran `init` and wrote `~/.nockguard/policy.yaml`, and `nockguard audit verify --help` returned an error.
- Audit rows are timestamped after the append lock is taken, so row times follow file order. This keeps a time-window proof from missing a row that was stamped before the capture but written after it.

## [0.3.0] - 2026-10-01

First release with binary assets attached.

### Added
- `nockguard mcp-gateway --config <path>`: an authenticated single-agent MCP
  gateway, run as an OAuth protected resource on loopback. Each request is
  checked by RFC 7662 token introspection (issuer, audience, subject, client,
  scope, active and unexpired) before any policy or upstream work, and NockCC
  tokens are not accepted. Sessions are bounded and isolated while the agent's
  quotas, trust score and audit trail are shared. Startup requires Ed25519
  audit signing. Inbound credentials are stripped, and only an
  environment-backed `X-Agent-Token` goes upstream. Nothing is deployed by this
  change; limits and the cutover are in `docs/design/hosted-gateway.md`.
- `nockguard-wall --agent <name>` selects that agent's audit trail and Ed25519
  public key environment variable. Explicit `-audit` and
  `-verify-ed25519-pub-env` values take precedence. Agent names go through the
  shared policy validator, which now also rejects `.` and `..` for proxy
  callers as well as the Wall.
- `release-assets` workflow: when a release is published, builds nockguard for
  linux and darwin on amd64 and arm64, writes `SHA256SUMS`, and attaches the
  four `nockguard_<version>_<os>_<arch>.tar.gz` archives. It fails the run if
  the tag differs from the output of `nockguard version`. Manual
  `workflow_dispatch` runs are a dry run that only uploads workflow artifacts.

### Fixed
- Gateway: record audit decisions durably before forwarding a tool call and
  before returning its result. A writer failure stops every session sharing it
  until storage is repaired and the gateway restarted, and errors after
  forwarding say the tool may have executed and must not be retried
  automatically. Stdio and `mcp-listen` audit behavior is unchanged.
- Gateway: in required-audit mode, withhold JSON and SSE tool replies that are
  not a matching JSON-RPC result or error, or that fail in transport, and
  return an error that keeps the request ID and warns against automatic retry.
  Non-2xx replies keep the upstream status and its `WWW-Authenticate`,
  `Retry-After` and `Mcp-Session-Id` headers.
- Gateway: scrub injected credentials from buffered and streaming responses,
  authenticate a request before it reserves an inflight slot, reject
  conflicting case-folded `params` keys, and fail closed on composite JSON-RPC
  IDs.
- CI: allow the `nock-fleet` GitHub App to trigger Claude Code Review. Wildcard
  bot access stays disabled.

## [0.2.0] - 2026-09-26

### Fixed
- Correct hosted-connector deployment guidance: cloud clients need a reachable
  authenticated gateway, with explicit agent identity and session isolation,
  before the separately approved live cutover.
- Reject missing, invalid, zero, and negative rate-limit windows at policy load
  time, including default-agent policies.
- Show redacted MCP argument scalars in approval prompts so amounts and targets
  are visible, without exposing nested values or envelope metadata.
- Preserve pagination and tool metadata when hiding denied tools; apply the same
  filtering to HTTP JSON and streamed SSE discovery responses, with bounded
  inspection and empty arrays when all tools are hidden.
- Recover the actual audit entry count after a lagging checkpoint, under the
  writer lock, without accepting truncated or tampered trails.
- Strip every inherited per-agent signing seed from upstream child processes,
  including keys belonging to agents absent from the active policy.
- Canonicalize nested tool arguments before validation and forwarding, closing
  duplicate-object parser differences while preserving exact numeric literals.

### Added
- `nockguard selftest` — proof-of-block self-test (N9070). Proves the live
  enforcement path actually **blocks**: a policy-denied canary tool is denied at
  the proxy gate, and a synthetic secret-shaped argument is caught by input
  validation. Distinct from `audit verify`, which proves audit-**trail**
  integrity. Each check runs a positive control (the probe must forward *without*
  the control under test) so a block is real, not a setup error; a positive-
  control miss is `SKIP`, never `PASS`. Exit `0` = enforcement proven, `2` = a
  gap, `1` = inconclusive (including no active policy). Supports `--json`.
- `policy.LoadBytes` — parse a policy from raw YAML through the same loader and
  validation as `policy.Load`.
- Auditable references (observe mode) — extracted NockCC card IDs and GitHub PR
  references now appear in audit trail entries, linked to the specific tool calls
  that acted for them. New audit-row fields `nock_id`, `pr`, `review_id`, and
  `parent_audit_seq` are populated by declared extractors for known MCP tools
  (nockcc_nock_claim, nockcc_nock_update, nockcc_nock_get, nockcc_nock_release).
  These fields are included in the Ed25519 signature chain, so they are tamper-evident.
  Extraction is conservative: unknown tools and malformed arguments yield no fields.
  Session-scoped "current card" stamp carries the card across calls within a
  single proxy session so rows that don't name the card in their own arguments
  still link to it. Released when nockcc_nock_release is forwarded. See README
  "Auditable References" section for examples.
