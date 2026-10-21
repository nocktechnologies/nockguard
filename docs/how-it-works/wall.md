# Local Live Wall

Follow [Install](../../README.md#install) for Homebrew or a release archive;
both provide `nockguard` and `nockguard-wall`. Then run:

```bash
nockguard wall --agent coder
```

The command opens a loopback dashboard at
`http://127.0.0.1:8787`. It reads and streams decisions, not tool arguments.
Requests must use `127.0.0.1`, `localhost`, or `[::1]` as the Host with the
configured port. `--allow-host <name>` accepts one additional Host name.
Serving on a non-loopback `--addr` requires `--allow-remote` and prints a
warning. Remote clients also need `--allow-host` set to the Host name or
address they use. `--addr` accepts numeric ports, including `0` for an
automatically chosen port. `/events` and `/export` reject cross-site browser
requests. This Origin check expects direct HTTP; TLS fronting is not supported.
`--agent` selects one Guard trail; `--lock-db` adds a read-only NockLock SQLite
log to the display. The PROOF export covers Guard rows only. Source:
`cmd/nockguard-wall/main.go`, `cmd/nockguard-wall/lock.go`,
[README Wall guide](../../README.md#live-wall),
[offline proof limits](../verifying-the-trail.md).

Session badges are local snapshots with refresh, row-count, key and external
anchor limits. `UNVERIFIABLE` is never a green verdict. A missing key or
large/unreadable Lock log cannot prove protection. For a combined offline
check, use `nockguard verify --session` with both logs and public keys.
Source: `cmd/nockguard-wall/sessions.go`,
`internal/sessionverify/sessionverify.go`.

The opt-in NOTIFY toggle shows a desktop notification, while the tab is hidden, for
rows that would beep (any `block` or critical catch), at most one per 10 seconds
with the rest collapsed into "+N more", and once per audit-chain break.
