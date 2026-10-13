# Install, first run, verify

For the steps below, [install NockGuard](../../README.md#install) first.
The [README quickstart](../../README.md#see-it-in-30-seconds) gives a complete
MCP client example using the generated `coder` policy with audit enabled.

1. Run `nockguard init` to write `~/.nockguard/policy.yaml`. It keeps an
   existing file unless `--force` is given. Review the generated `coder` rules.
2. Run `nockguard keygen --agent coder`. The private seed is stored at mode
   `0600` in `~/.nockguard/keys/coder.ed25519`; `coder.pub` is the public key.
   `--print-env` prints the seed, so avoid it in a captured terminal.
3. Replace one MCP server command in the client config with
   `nockguard proxy --upstream "<existing server command>" --agent coder`.
   Restart the client and call an allowed tool. Only wired traffic is gated.
4. Run `nockguard verify --agent coder` for the signed trail and
   `nockguard selftest` for synthetic deny and validation probes. Selftest does
   not certify the live client route. See [exit codes](../specs/cli-policy.md).

From a source checkout, `python3 scripts/quickstart-acceptance.py` runs an
isolated allow/deny check with a local MCP stub. CI runs it on Linux; it does
not certify a customer's connector.

Source: `internal/policy/init.go`, `cmd/nockguard/keygen.go`,
[cmd/nockguard/main.go](../../cmd/nockguard/main.go), [cmd/nockguard/selftest.go](../../cmd/nockguard/selftest.go),
`scripts/quickstart-acceptance.py`, [.github/workflows/ci.yml](../../.github/workflows/ci.yml).
