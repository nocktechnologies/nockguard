# CLI, policy and exit-code contract

This records the current source surface. [cmd/nockguard/main.go](../../cmd/nockguard/main.go)
dispatches commands and lists their flags in `printUsage`.

| Command | Purpose |
| --- | --- |
| `init [--policy PATH] [--force]` | Write the starter policy. |
| `proxy --upstream CMD --agent NAME [--policy PATH] [--audit-best-effort]` | Gate one stdio MCP server; `--agent` is required unless zero-config observe applies (see below). |
| `mcp-http --upstream URL --agent NAME [--policy PATH] [--auth-env ENV] [--audit-best-effort]` | Observe-only stdio-to-HTTP bridge. |
| `mcp-listen --listen 127.0.0.1:PORT --upstream URL --agent NAME [--policy PATH] [--audit PATH] [--audit-best-effort]` | Local HTTP enforcement listener. |
| `mcp-gateway --config PATH` | Single-agent OAuth resource gateway; see [gateway contract](../design/hosted-gateway.md). |
| `wall [--agent NAME] [--audit PATH] [--demo]` | Launch the companion Live Wall binary; see [Install](../../README.md#install) for both binaries. |
| `egress-proxy --listen ADDR --agent NAME [--policy PATH] [--audit PATH] [--enforce] [--allow-remote]` | Explicit HTTP/CONNECT proxy; policy observe-only without `--enforce`. |
| `verify` / `audit verify` | Verify one trail via `--agent`, `--key-env`, or `--ed25519-pub-env`; `--all`, `--session` and `--export` select their own modes. |
| `selftest [--policy PATH] [--json]` | Synthetic positive-control enforcement check. |
| `policy check --policy PATH` | Load the file with the proxy's loader and nothing else; exit 0 loaded (warnings go to stderr), 1 not. |
| `policy propose`, `policy shadow-report` | Build and inspect observe-to-enforce candidates from a trail. |
| `trust show --agent NAME` | Read the opt-in trust score. |
| `evidence --framework soc2 ...` | Create local evidence pack; HTML or JSON. |
| `approvals list\|approve ID\|deny ID\|prune` | Operate local-socket approvals. |
| `keygen [--agent NAME] [--force] [--print-env]` | Write one keypair; `--print-env` prints the secret seed and public key as env assignments instead of writing files. |
| `version`, `--help`, `-h` | Print version or usage. |

`--audit-best-effort` is available only on local `proxy`, `mcp-http`, and
`mcp-listen`; it allows calls through after local audit-write failures,
weakening fail-closed audit enforcement. `mcp-gateway` has no such option and
requires auditing to be enabled.

`proxy`, `mcp-http`, `mcp-listen`, `egress-proxy`, and `init` use Go's standard
flag parser. Unknown flags, missing flag values, and unexpected positional
arguments return an error before setup. Both `--policy PATH` and
`--policy=PATH` count as explicitly choosing a policy for `proxy`.

`egress-proxy --listen` requires an explicit loopback host (`127.0.0.1`,
`localhost`, or `::1`) unless `--allow-remote` is passed. Remote binds print a
warning: the proxy has no caller authentication, so restrict access with external
network controls. `localhost` binds IPv4 loopback.

Only zero-config observe mode permits omitting `proxy --agent`: this applies
when no `--policy` flag is supplied and the default
`~/.nockguard/policy.yaml` file does not exist. In every other case, `--agent` is required, including when an explicit
policy path cannot be loaded.

Default policy: `~/.nockguard/policy.yaml`; default audit root:
`~/.nockguard/logs/`. `verify --agent NAME` uses the per-agent trail and
public key from `NOCKGUARD_AGENT_<NAME>_ED25519_PUB` or the matching `.pub`
file. Key file and environment precedence is in `internal/policy/agentkeys.go`.
`--all` is not a substitute for `--session`: the latter checks a specified
NockLock DB and Guard trail together ([cmd/nockguard/verify_session.go](../../cmd/nockguard/verify_session.go)).
For a single signed trail, `verify --completeness` adds per-run assessments to
the integrity verdict. It requires the same snapshot to pass signature and
checkpoint verification. `LIMITED` is the highest completeness result and
means the recorded observation stream is internally complete, not that every
attempt was recorded or a remote side effect completed. `--all`, `--session`,
and `--export` retain their own verification scopes.

## Policy YAML

Top level `agents` maps agent names to policies; `agents.default` is the fallback.
Top level `audit` is optional. Source: [internal/policy/policy.go](../../internal/policy/policy.go).

| Key | Current meaning |
| --- | --- |
| `agents.<name>.allow`, `deny`, `ask`, `shadow`, `require_approval` | Tool patterns; `deny` wins, `ask` holds, `shadow` observes, `require_approval` is the legacy gate. |
| `agents.<name>.deny_methods` | Exact, case-sensitive non-`tools/call` MCP method names to refuse before forwarding; no globs, empty entries or whitespace. Omitted means pass through with method-only auditing when enabled. Uses the named policy or `default` fallback. |
| `agents.<name>.mode` | Explicit `allow` permits tools without an allow list; `deny` blocks them. Omitted mode and no allow list deny by default; an allow list denies unmatched tools. |
| `agents.<name>.fail_mode` | `deny` (default) or `ask` for malformed or ambiguous `tools/call` messages. |
| `agents.<name>.validate_input` | Opt-in `sqli`, `path_traversal`, `secrets` categories. |
| `agents.<name>.block_params` | Custom argument regexes. |
| `agents.<name>.rate_limit` | `max_calls` and positive Go-duration `window`; sliding window. |
| `agents.<name>.spend_cap` | `max_calls` cumulative for the proxy session; not dollar spend. |
| `agents.<name>.trust` | `enabled` and optional `path`; changes only rate-limit headroom. |
| `agents.<name>.inject` | Rules with `tools`, `ref`, `arg`, optional `template`; see [injection limits](../how-it-works/approvals-and-injection.md). |
| `agents.<name>.tool_pins` | Operator-authored map of stable upstream ID to exact tool name to `{hash_version: jcs-rfc8785-v1, sha256: <64 lowercase hex>}`. Every configured pin is enforced. Requires signed `audit.action_pairing`. |
| `agents.<name>.strict_tool_pins` | Opt-in requirement that every policy-allowed tool have a matching pin; missing, stale, unhashable and changed definitions are blocked. Requires signed `audit.action_pairing`. |
| `audit` | `enabled`, optional `path`, `sign_key_env` (HMAC), `sign_ed25519_key_env` (Ed25519), optional `forward` with `enabled`, `url`, `api_key_env`. |

To approve a tool definition, first run a signed action-pairing observe session,
inspect the signed `tool_definition_hash` for a complete single-page listing,
then edit the operator-owned policy to copy that value into `tool_pins`. For
example, `tool_pins: {filesystem-local: {read_file: {hash_version:
jcs-rfc8785-v1, sha256: <reviewed 64-character digest>}}}` under the agent.
Launch `nockguard proxy` with `--upstream-id filesystem-local`; the ID is an
operator-chosen stable label, not a command or URL. A review and policy change
are required to approve a changed definition. `tools/list` and per-call
approval cannot rewrite the pin. Pinning currently supports the stdio proxy.

The key names and nested shapes are Go YAML fields in
[internal/policy/policy.go](../../internal/policy/policy.go); the detailed policy examples and validation
rules are in the [README](../../README.md#policy-rules). Signing fields name
environment variables; they never contain key values. Unknown agent names and
invalid policy values must not silently grant access.

## Exit status

| Command | `0` | `1` | `2` |
| --- | --- | --- | --- |
| `verify --agent` / `--key-env` / `--ed25519-pub-env` | Trail is non-empty and fully checkpointed | Setup/key error, `NO_ROWS` or `UNANCHORED` | Trail read or integrity failure after key selection |
| `verify --all` | Every requested trail is non-empty and fully checkpointed | Setup/key error, any `NO_ROWS`, `UNANCHORED` or unverifiable trail, or no trails | Any trail read or integrity failure after key selection |
| `verify --export` | Export proof verified (completeness stated separately) | Setup, key or file-read error | Invalid signed proof |
| `verify --session` | `PROTECTED` | `UNVERIFIABLE`, `UNSIGNED`, `NO_ROWS`, `UNANCHORED` or setup error | `TAMPERED` |
| `selftest` | At least one check passed, none failed | Inconclusive setup or all checks skipped | Enforcement gap |
| `evidence` | Integrity verified | Setup/input error | Broken chain; pack still produced |
| Other commands | Success | Usage or runtime failure | Command-specific; do not assume `2` means tampering |

`verify --completeness` keeps the integrity-only exit status; BROKEN, INCOMPLETE or UNASSESSABLE completeness verdicts do not change the exit code; read `completeness[].verdict` in --json. The `completeness` array is present only when the integrity verdict is `PROTECTED`; any other verdict, or a key or read error, produces no completeness output.

Parse `--json` for scripts where offered. Text output is for humans. Sources:
[cmd/nockguard/main.go](../../cmd/nockguard/main.go),
[cmd/nockguard/verify_export.go](../../cmd/nockguard/verify_export.go),
[cmd/nockguard/verify_session.go](../../cmd/nockguard/verify_session.go),
[cmd/nockguard/selftest.go](../../cmd/nockguard/selftest.go).
