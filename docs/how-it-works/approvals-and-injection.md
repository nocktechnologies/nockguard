# Approval and credential injection

An `ask` verdict withholds a call until an approver accepts it. Denial,
timeout or no approver prevents forwarding. `NOCKGUARD_APPROVER=local` uses a
Unix socket; a dedicated Telegram bot is also implemented. The local socket
checks ownership and modes, but a same-uid agent can approve its own call.
Use a separate uid or filesystem fence where that matters. When a local socket
decision is recorded, the signed audit row includes `approval_actor` as
`local:uid:<decimal>` from the OS-reported Unix peer UID. This identifies the
approver process's uid, not a person or a particular executable; no PID or
executable identity is claimed. The value is taken from kernel peer credentials,
not a JSON field supplied by the socket client; local requests with unknown
identity fields are rejected without consuming the held decision. Test-seam, Telegram, timeout,
and other non-local outcomes omit it. Source:
[cmd/nockguard/main.go](../../cmd/nockguard/main.go), `internal/approval/local.go`,
[README approval guide](../../README.md#policy-rules).

`inject` resolves `env:`, protected `file:` or `nockcc:` references only for
allowed `tools/call` requests, then overwrites a named JSON argument path.
Missing secrets and invalid paths block the call. The upstream tool receives
the plaintext credential; injection keeps it out of the original agent
context, not out of the tool. Keep tool patterns narrow. Source:
`internal/secrets/secrets.go`, `internal/proxy/inject.go`,
[README policy rules](../../README.md#policy-rules).
