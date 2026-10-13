# Policy, validation and limits

Policies are per agent, with an optional `default` fallback. Verdict order is
`deny`, `ask`, then `allow`/`mode`. Malformed tool patterns and unknown
`validate_input` categories are load errors. `shadow` records `would-deny`
without blocking. Source: `internal/policy/policy.go` and its
`*failopen_test.go` guards. The [policy contract](../specs/cli-policy.md)
lists keys and defaults.

`validate_input` and `block_params` inspect arguments after policy allows a
call. `rate_limit` counts calls in a sliding Go-duration window; `spend_cap`
counts calls for the proxy session and never refills. Both measure MCP tool
calls, not money or model tokens. `trust` is opt-in and changes only the rate
cap. Source: `internal/validate/validate.go`,
`internal/ratelimit/ratelimit.go`; see [trust scoring](../TRUST.md).

Use `policy propose` and `policy shadow-report` during an observe window
before switching to `mode: deny` ([cmd/nockguard/main.go](../../cmd/nockguard/main.go)). No policy
governs calls that bypass the configured proxy.
