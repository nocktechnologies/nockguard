# Pool router status

`nockguard-pool` is a scaffold. `validate <pool.yaml>` loads a configuration;
`serve <pool.yaml>` exits with “not implemented” and does not route traffic.
The [V1 contract](../POOL_ROUTER.md) describes the intended router and its
limits, not a working service. Do not point an agent's model traffic at it yet.
Source: `cmd/nockguard-pool/main.go:1` and `internal/pool/config.go`.
