# Audit or gateway incident

1. Stop sending new tool calls through the affected route. Record the process,
   agent, trail path, time and upstream request IDs without copying secrets or
   tool arguments into the incident record.
2. Run `nockguard verify --agent <agent> --json` or the explicit trail/key mode.
   Exit 2 means a trail read failure or failed integrity check, not necessarily
   tampering. Inspect the JSON `error` (or stderr): file/permission errors
   indicate a read failure; hash, signature or checkpoint errors indicate an
   integrity failure. Exit 1 means verification was inconclusive.
   For a combined NockLock session, use `verify --session` with both explicit
   paths and public keys. Preserve the original logs and `.hwm` head together.
3. For a required-audit `mcp-gateway` failure, inspect the upstream service
   before retrying any call: a failed response can follow a successful side
   effect. Repair storage, verify the signed trail, then restart the gateway;
   filesystem repair alone does not clear its failed writer.
4. For stdio `proxy` or local `mcp-listen`, treat audit-write errors as possible
   evidence gaps because those paths may continue forwarding. Review upstream
   state and the policy, then decide whether to stop the route until evidence
   is available. Do not describe a clean trail as proof of calls that never
   reached that trail.
5. Capture a Wall PROOF export only for Guard rows and consult
   [the proof limits](../verifying-the-trail.md). Restore the prior endpoint and
   auth setup if a deployed gateway must be rolled back.

Source: `cmd/nockguard/main.go:820`, `internal/proxy/required_audit.go`,
`internal/proxy/stdio.go`, [gateway failure contract](../design/hosted-gateway.md),
[N8761 rollback plan](../design/n8761-phase0-http-listener-forward-proxy.md).
