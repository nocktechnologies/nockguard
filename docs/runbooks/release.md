# Release

## Change promotion

Keep each PR focused on one issue or internal tracking card and target `next`.
Maintainers gate the automated two-model review and the `CodeRabbit`,
`build-test`, `macos-test`, `claude-review`, and `scan` checks on the exact PR
head. A passing or skipped check does not replace review of the findings.
Re-run checks and review after every new commit. The `ci` workflow runs Linux
and macOS checks on pushes to both `next` and `main`.

Prepare the version and changelog on `next` before promoting a release
candidate with a squash PR from `next` to `main`. Require the
same exact-head reviews and checks on that PR, then wait for the checks on the
resulting `main` head before tagging. Branch rules are maintained separately;
do not weaken existing protections to make promotion pass.

## Release checks

1. On the candidate branch, choose the release tag and update the hardcoded
   version in `cmd/nockguard/main.go`, `docs/ROADMAP.md`, and `CHANGELOG.md`.
   Verify customer docs against the code that will ship, then promote the
   candidate through the release PR above.
2. Run the [CI checks](../../CLAUDE.md#build-and-test), including the
   [macOS test job](../../.github/workflows/ci.yml), against the exact `main`
   commit selected for release.
3. Run `scripts/build-release-assets.sh vX.Y.Z dist` on Linux with GNU tar and
   `sha256sum`. It builds four archives containing `nockguard` and
   `nockguard-wall` (Linux/macOS, amd64/arm64) and `SHA256SUMS`; run
   `scripts/check-release-version.sh vX.Y.Z <binary>`. Run
   `govulncheck -mode=binary` on both binaries in each archive. The build script
   rejects wrong tag syntax; the version checker rejects a version mismatch.
4. Use `workflow_dispatch` on `release-assets` for a dry run; it uploads CI
   artifacts only. After maintainer review, publish the tag/release from the
   selected `main` commit. The published release workflow rechecks checksums
   and attaches archives and `SHA256SUMS`.
5. A maintainer updates the Homebrew tap, then downloads each intended platform
   archive, checks its SHA256 against `SHA256SUMS`, and runs `nockguard version`
   plus the customer quickstart on a clean host before announcing the release.

Source: `.github/workflows/release-assets.yml`,
`scripts/build-release-assets.sh`, `scripts/check-release-version.sh`.
