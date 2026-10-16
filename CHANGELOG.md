# Changelog

All notable changes to NockGuard are documented here.

## [Unreleased]

### Changed

- `egress-proxy` requires a loopback listen address unless `--allow-remote` is passed; remote binds print a warning.

### Fixed

- `policy propose` verifies its audit input and lists tool names containing glob characters as comments instead of rules.
- `mcp-listen` validates loopback Host headers, rejects browser Origin headers and requires `application/json` requests before forwarding.
- Non-tool MCP methods now record distinct `method-allow` / `method-deny` audit decisions, excluded from tool proposals and tool decision counts. Method rows are written immediately; denied requests return JSON-RPC `-32601`. The optional per-agent `deny_methods` list refuses exact method names before forwarding; other methods continue to pass through by default.
- The HTTP MCP bridge forwards canonical messages so forwarded tool calls and their audit records agree, and returns an invalid-request error for rejected requests with an ID instead of leaving clients waiting.
- Stdio MCP rejection messages use "ambiguous message key" for conflicting method or params aliases.
- The upstream MCP child no longer inherits the configured audit-forwarder API key.

## [0.8.0] - 2026-10-15

v0.8.0 fixes policy patterns that use `?` or character classes, which loaded without error but matched only as literal text. The Wall now checks the Host of every request and serves only on loopback unless you opt in. Local approvals record the approver's UID in the signed trail, and an opt-in audit mode pairs each tool call with its observed outcome.

### Upgrade notes

- Policy rules that contain `?` or `[` now act as glob patterns in deny, ask, require_approval, allow, shadow and inject rules. Before this release they loaded as globs but matched as literal text. In a pattern that contains `*`, `?` or `[`, a backslash escapes the next character. Review any rule that uses these characters for a literal tool name.
- The Wall refuses a non-loopback `--addr` unless you pass `--allow-remote`. Remote clients also need `--allow-host`.

### Security

- Policy patterns with `?` and character classes now match as globs. A deny rule such as `exec?` loaded without error but did not deny `exec1`. Validation, evaluation and inject conflict checks now share one glob test. `*` and `?` do not match `/`.
- The Wall validates the Host header on every route, with one optional extra host from `--allow-host`. Event and export routes also check the browser `Origin` and `Sec-Fetch-Site` headers. A remote bind needs `--allow-remote` and prints a warning. A named port is rejected at startup.

### Added

- Local approvals record a signed `approval_actor` (`local:uid:<n>`) taken from the kernel peer-UID check. It identifies the UID of the approving process, not a person. Ordinary tool-call rows and non-local approvals do not carry it. Local decision JSON with unknown identity fields is rejected before the held call is consumed.
- Opt-in action pairing for stdio (`audit.action_pairing: true`). The decision, the dispatch and the observed result of each `tools/call` share one action ID. A matching response is recorded as `response_observed`; a timeout, cancellation, disconnect or shutdown is recorded as `outcome_unknown`. No request IDs, arguments or response bodies are written. Pairing needs required audit writes and cannot be combined with `--audit-best-effort`. Older binaries cannot verify trails that contain these rows, so use a dedicated audit path. See `docs/how-it-works/audit.md`.

### Fixed

- Evidence packs parse audit entries and verify their chain and checkpoint from the same snapshot, so contents and verdict agree while the file is being replaced.

### Changed

- The Wall decision filter lists every decision the audit log writes. It adds tiles for approvals granted, dispatched and would-deny (observe), with matching `/pulse` counts and an "other" bucket for unknown values. `--demo` shows each tile.
- The public repository no longer carries internal launchers, tool names, local paths or host examples. The quickstart demo uses a self-contained local MCP stub.

### Documentation

- The README quickstart uses a physical fixture path, absolute executable paths and an explicit client `PATH`.
- The CLI reference and `--help` match current behavior, including `--audit-best-effort`, the optional egress policy and when `--agent` may be omitted.
- Warden policy suggestions cite a primary source for each proposed rule, or say that none was found.
- New design note for the additive action and lifecycle audit contract.

## [0.7.1] - 2026-10-14

### Documentation
- README shows the Live Wall over a real signed trail, CONTRIBUTING lists the checks CI runs (`gofmt`, `go test -race`, the Wall browser test and the quickstart acceptance), and the approvals page links to the README policy rules section.
- CI runs Linux and macOS checks on `next`; contributor and release guides define exact-head PR checks and the `next` to `main` release promotion (N11741).

### Fixed
- `mcp-gateway` releases an SSE initialize session before delivering its matching result, so an immediate follow-up does not receive a spurious `429 gateway busy`.
- `mcp-gateway` also installs and releases a validated JSON initialize session before delivering its result, so an immediate follow-up does not receive a spurious `429 gateway busy`.
- The vuln-scan helper (`.claude/commands/vuln-scan.md` and the Warden template copy) shows the `verify --all` command again and rates a `[SKIP]` line (invalid agent name) as HIGH.
- `mcp-gateway` refreshes the idle timeout after a JSON or SSE initialize result finishes writing, without overwriting the state of a follow-up already in progress.
- Release builds ignore the local `dist/` directory, so release binaries no longer report a modified source tree (`+dirty`, `vcs.modified=true`).

## [0.7.0] - 2026-10-14

### Fixed
- `verify` and `verify --all` report empty signed trails as `NO_ROWS` and trails beyond their signed checkpoint as `UNANCHORED`; only non-empty, fully checkpointed trails report `PROTECTED`.
- Evidence packs now mark empty trails `NO_ROWS` and trails beyond their signed checkpoint `UNANCHORED`, matching CLI and Wall verification.
- Build CI and release archives with Go 1.26.9 and gate source and release binaries with `govulncheck`.
- `nockguard proxy` now starts a one-second shutdown deadline when the upstream dies, even while the client holds stdin open or stops reading stdout. It sends JSON-RPC `-32603` errors for in-flight requests when the client can receive them, then stops the upstream process group and exits nonzero.
- `verify --agent` now verifies an explicitly supplied `--audit` file instead of silently checking the agent's default trail.
- The stdio proxy registers response correlation before writing a request upstream, and clears pending state and resolves its audit sequence when the write fails.
- `nockguard proxy` keeps delivering output the upstream wrote before it exited while the client is still reading. Shutdown waits for the client to go idle for one second, up to a ten-second cap.

### Changed
- The Wall no longer scrolls horizontally on narrow screens (390 px): filters and tiles wrap, feed rows stack, and the evidence scope notes sit behind an "Evidence details" toggle on narrow screens (open by default on wide ones).
- `tools/list` now keeps tools with an `Ask` verdict visible while holding their calls for local or Telegram approval; denied tools stay hidden. Approved calls record their final `allow` audit row before dispatch.
- The Wall counts audit records, not calls, and says so: the header reads "records in view" and "threat records". `tools/list` hides now show as a separate "tools hidden" count and no longer count as rejected records, threats or toward the rejected share, so one rejected call no longer reads as 13 threats caught.

### Documentation
- Correct Wall installation guidance and replace source line references with file links.
- Correct the `/policy-lint`, `/vuln-scan` and `/threat-model` helper commands, the Warden `CLAUDE.md` and README, and the model-API egress template against the engine: unknown keys fail the load, `mode` defaults to deny, the full agent key list, per-agent audit trails and `keygen --agent`, `egress-proxy --enforce`, and the SSRF guard. A test now keeps the Warden command copies identical to `.claude/commands/` and the lint key list in step with `AgentPolicy`.
- Document Homebrew and Linux archive installation, including the Live Wall.
- Linux install verifies the release archive against SHA256SUMS before installing.
- The `/vuln-scan` helper and the Warden `CLAUDE.md` read the `verify` verdict line before labeling an exit 1, so an empty trail (`NO_ROWS`) and a trail past its signed checkpoint (`UNANCHORED`) are no longer reported as a missing key.

## [0.6.0] - 2026-10-13

### Breaking
- Local `nockguard proxy` and `mcp-listen` (and `mcp-http`) now refuse tool calls when a required audit write fails, whenever auditing is enabled. The failure latches: every later call is refused until the trail is fixed and reopened with a verified signing key. Pass `--audit-best-effort` to get the old forwarding back; startup prints a warning. `status`, `doctor` and the Wall show `audit failing: calls refused` while a failure is outstanding.
- `nockguard proxy` and `mcp-listen` now write a `dispatch` audit row before they forward an allowed `tools/call` request, when auditing is on and `--audit-best-effort` is not set. Each such call has one more row than in 0.5.0. Denied calls, other methods and `mcp-http` write no `dispatch` row, and `mcp-gateway` already wrote one. Anything that counts rows or matches decisions should expect `dispatch`.
- `nockguard init` writes a different starter policy. The agent is `coder` (was `my-agent`), it allows `read_file` and `read_text_file` and denies `write_file`, `default` stays `mode: deny`, and `audit.enabled: true` is on (it was commented out). The old `ask` rules and wildcard allows are gone. Run `keygen --agent coder` before the first proxy run so the audit trail is signed. Existing policy files are not touched, and `init` still refuses to overwrite one without `--force`.
- The Wall now reads the agent's public key with the same resolver as `nockguard verify --agent`: the `NOCKGUARD_AGENT_<NAME>_ED25519_PUB` variable first, then `~/.nockguard/keys/<name>.pub`. A Wall that relied on a key being absent will now verify against the file. `/verify` reports PROTECTED only for a non-empty trail that its signed checkpoint fully covers; empty, unconfigured, unavailable and unanchored trails are shown as such.

### Added
- Local approver for `ask` verdicts, with no network: set `NOCKGUARD_APPROVER=local` and decide held calls with `nockguard approvals list|approve|deny` (`prune` removes dead sockets left by crashed proxies). Held calls wait on a `0600` unix socket in a `0700` approvals directory, one `<pid>-<random>.sock` per proxy, removed on exit, and are audited as `approval-granted` / `approval-denied` with the approver `local:<uid>`. The listing shows id, agent, tool, reason and age, never arguments. The approver does not start, and `ask` fails closed, if the directory or socket permissions, ownership or type are wrong. A same-uid agent can still approve its own calls; see the README trust boundary.
- Live Wall shows NockLock and NockGuard in one stream. `nockguard-wall --lock-db <events.db>` reads a NockLock log read-only (file, network and secret fence events, blocked and passed), labeled `LOCK` / `GUARD` and colored by outcome, decision only. `--lock-pub-env` names the NockLock public key (default `NOCKLOCK_AUDIT_ED25519_PUB`). `--demo` cannot be combined with `--lock-db`.
- Per-session signed-proof badge on the Wall (`GET /sessions`): the same verdict as `nockguard verify --session` (PROTECTED / TAMPERED / UNSIGNED / UNVERIFIABLE / NO_ROWS / UNANCHORED) with both key fingerprints. A missing key is UNVERIFIABLE, never green. A Lock log over 100,000 events is UNVERIFIABLE, too large. An unreadable Lock row shows as UNPARSEABLE and makes its session UNVERIFIABLE; the rest of the batch still shows.
- `nockguard wall` subcommand. It starts `nockguard-wall` from beside the CLI or from `PATH` and forwards flags and signals. `nockguard-wall` now ships in the Linux and macOS release archives, and a standalone `nockguard-wall` install keeps working.
- `nockguard status --agent <name>` and `doctor` report a required audit write failure; `status` accepts `--audit <path>` for custom trail paths.
- A Linux CI check runs the README quickstart end to end (init, keygen, proxy, verify) against a local MCP stub, with a successful read, a blocked write and signed allow and deny rows.

### Changed
- `/export` CSV and JSON gain a trailing `source` column / field (`GUARD` or `LOCK`). With `--lock-db`, each source keeps its own 500-row cap, and the `X-NockGuard-Lock-Verification` response header is `ok`, `unsigned` (no Guard key, so nothing is verified) or `unavailable` (no Lock snapshot, so no Lock rows). The PROOF export remains NockGuard rows only.
- The README quickstart uses the `coder` agent and a concrete demo path, matching `nockguard init`.
- Documentation claims are aligned with shipped behavior, and a repository map and the 1.0 contract are added under `docs/`.

### Fixed
- macOS: the local approver socket path now fits the 104 byte `sun_path` limit. When `~/.nockguard/approvals` would be too long, it falls back to a private per-user directory under `/tmp`.
- macOS 26.5: two nockguard processes starting at once on a fresh machine no longer fail with "opening key lock ... no such file or directory".

### Known limits
- With stdio, a response that arrives ahead of an earlier pending call can be released before its deferred decision row is written. The `dispatch` row is durable first. If that later write fails, the latch refuses every later call and status reports the failure.
- The failure marker is per trail, not per process or per agent. Every proxy writing the same trail sees it.
- An unsigned trail has no verified reopen, so nothing clears its failure marker short of choosing `--audit-best-effort`. Sign the trail to get the repair path.

## [0.5.0] - 2026-10-10

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
- `mcp-gateway` no longer opens or creates the policy-wide audit trail when it refuses to start for lack of a per-agent signing key, and the refusal now names the cause: the policy's `sign_key_env` / `sign_ed25519_key_env` takes precedence, or no per-agent key was found.

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
