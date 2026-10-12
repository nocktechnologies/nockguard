# Local Live Wall

`go run ./cmd/nockguard-wall` opens a loopback dashboard at
`http://127.0.0.1:8787`. It reads and streams decisions, not tool arguments.
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
