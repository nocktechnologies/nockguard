# 002 — Sign per-agent trails with local key files

**Decision.** Keep a private Ed25519 seed per agent in a protected local file,
with an environment variable override. Publish the matching `.pub` file for
offline verification. Do not print the seed in normal `keygen` output.

**Reason.** The verifier needs a public key, while the signer must keep the
private seed out of terminal scrollback and policy YAML.

**Consequence.** Key ownership/mode and public-key matching are operational
requirements. A valid trail plus its signed head can still be rolled back to
an earlier genuine state without a remote anchor.

Sources: [0.5.0 changelog](../../CHANGELOG.md#050---2026-10-10),
`cmd/nockguard/keygen.go`, `internal/policy/agentkeys.go`,
[trail verification limits](../verifying-the-trail.md).
