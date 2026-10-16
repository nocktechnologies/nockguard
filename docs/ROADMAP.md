# Road to 1.0

Updated 2026-10-16. Current source version: `v0.9.0`.

## Now

- Fail-closed audit is implemented for stdio, local HTTP, and the gateway;
  local transports offer an explicit best-effort opt-out. See the
  [audit boundary](how-it-works/audit.md).
- Linux and macOS race tests run in [CI](../.github/workflows/ci.yml).
- The Wall launcher, Homebrew package, and release archives include the
  companion binary (released in v0.6.0).
- Linux quickstart acceptance covers allowed/denied calls and signed verification
  with a local stub; it does not certify a hosted customer connector.

## Next

- Review and keep the [CLI, policy schema, and exit-code contract](specs/cli-policy.md)
  aligned with source; this fifth 1.0 gate is written for review.
- Verify all five release gates through CI or the stated customer check before 1.0.

## Later

- Release 1.0 once those gates are complete. Follow the
  [release runbook](runbooks/release.md) for packaging and version checks.
