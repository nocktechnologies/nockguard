# Release

1. Choose the release tag and update the hardcoded version in
   `cmd/nockguard/main.go:94`. Update `CHANGELOG.md` and verify customer docs
   against the code that will ship.
2. Run the [CI checks](../../CLAUDE.md#build-and-test). The current CI job is
   Linux only (`.github/workflows/ci.yml:13`); the 1.0 bar requires macOS CI.
3. Run `scripts/build-release-assets.sh vX.Y.Z dist` on Linux with GNU tar and
   `sha256sum`. It builds four archives containing `nockguard` and
   `nockguard-wall` (Linux/macOS, amd64/arm64) and `SHA256SUMS`; run
   `scripts/check-release-version.sh vX.Y.Z <binary>`. The build script rejects
   wrong tag syntax; the version checker rejects a version mismatch.
4. Use `workflow_dispatch` on `release-assets` for a dry run; it uploads CI
   artifacts only. After review, publish the GitHub release. The published
   release workflow rechecks checksums and attaches archives and `SHA256SUMS`.
5. Download each intended platform archive, check its SHA256 against
   `SHA256SUMS`, and run `nockguard version` and the customer quickstart on a
   clean host before announcing the release.

Source: `.github/workflows/release-assets.yml`,
`scripts/build-release-assets.sh`, `scripts/check-release-version.sh`.
