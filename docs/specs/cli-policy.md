# CLI, policy and exit-code contract

This records the current source surface. [cmd/nockguard/main.go](../../cmd/nockguard/main.go)
dispatches commands and lists their flags in `printUsage`.

| Command | Purpose |
| --- | --- |
| `init [--policy PATH] [--force]` | Write the starter policy. |
| `proxy --upstream CMD [--agent NAME] [--policy PATH]` | Gate one stdio MCP server; without an explicit policy or default file, starts observe mode. |
| `mcp-http --upstream URL --agent NAME [--policy PATH] [--auth-env ENV]` | Observe-only stdio-to-HTTP bridge. |
| `mcp-listen --listen 127.0.0.1:PORT --upstream URL --agent NAME [--policy PATH] [--audit PATH]` | Local HTTP enforcement listener. |
| `mcp-gateway --config PATH` | Single-agent OAuth resource gateway; see [gateway contract](../design/hosted-gateway.md). |
| `wall [--agent NAME] [--audit PATH] [--demo]` | Launch the companion Live Wall binary; see [Install](../../README.md#install) for both binaries. |
| `egress-proxy --listen ADDR --agent NAME --policy PATH [--audit PATH] [--enforce]` | Explicit HTTP/CONNECT proxy; policy observe-only without `--enforce`. |
| `verify` / `audit verify` | Verify one trail via `--agent`, `--key-env`, or `--ed25519-pub-env`; `--all`, `--session` and `--export` select their own modes. |
| `selftest [--policy PATH] [--json]` | Synthetic positive-control enforcement check. |
| `policy propose`, `policy shadow-report` | Build and inspect observe-to-enforce candidates from a trail. |
| `trust show --agent NAME` | Read the opt-in trust score. |
| `evidence --framework soc2 ...` | Create local evidence pack; HTML or JSON. |
| `approvals list\|approve ID\|deny ID\|prune` | Operate local-socket approvals. |
| `keygen [--agent NAME] [--force] [--print-env]` | Write one keypair; `--print-env` prints the secret seed and public key as env assignments instead of writing files. |
| `version`, `--help`, `-h` | Print version or usage. |

Default policy: `~/.nockguard/policy.yaml`; default audit root:
`~/.nockguard/logs/`. `verify --agent NAME` uses the per-agent trail and
public key from `NOCKGUARD_AGENT_<NAME>_ED25519_PUB` or the matching `.pub`
file. Key file and environment precedence is in `internal/policy/agentkeys.go`.
`--all` is not a substitute for `--session`: the latter checks a specified
NockLock DB and Guard trail together ([cmd/nockguard/verify_session.go](../../cmd/nockguard/verify_session.go)).

## Policy YAML

Top level `agents` maps agent names to policies; `agents.default` is the fallback.
Top level `audit` is optional. Source: [internal/policy/policy.go](../../internal/policy/policy.go).

| Key | Current meaning |
| --- | --- |
| `agents.<name>.allow`, `deny`, `ask`, `shadow`, `require_approval` | Tool patterns; `deny` wins, `ask` holds, `shadow` observes, `require_approval` is the legacy gate. |
| `agents.<name>.mode` | Explicit `allow` permits tools without an allow list; `deny` blocks them. Omitted mode and no allow list deny by default; an allow list denies unmatched tools. |
| `agents.<name>.fail_mode` | `deny` (default) or `ask` for ambiguous tool calls. |
| `agents.<name>.validate_input` | Opt-in `sqli`, `path_traversal`, `secrets` categories. |
| `agents.<name>.block_params` | Custom argument regexes. |
| `agents.<name>.rate_limit` | `max_calls` and positive Go-duration `window`; sliding window. |
| `agents.<name>.spend_cap` | `max_calls` cumulative for the proxy session; not dollar spend. |
| `agents.<name>.trust` | `enabled` and optional `path`; changes only rate-limit headroom. |
| `agents.<name>.inject` | Rules with `tools`, `ref`, `arg`, optional `template`; see [injection limits](../how-it-works/approvals-and-injection.md). |
| `audit` | `enabled`, optional `path`, `sign_key_env` (HMAC), `sign_ed25519_key_env` (Ed25519), optional `forward` with `enabled`, `url`, `api_key_env`. |

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

Parse `--json` for scripts where offered. Text output is for humans. Sources:
[cmd/nockguard/main.go](../../cmd/nockguard/main.go),
[cmd/nockguard/verify_export.go](../../cmd/nockguard/verify_export.go),
[cmd/nockguard/verify_session.go](../../cmd/nockguard/verify_session.go),
[cmd/nockguard/selftest.go](../../cmd/nockguard/selftest.go).
