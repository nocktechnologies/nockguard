# Release

## Change promotion

Keep each PR focused on one issue or internal tracking card and target `next`.
Maintainers gate the automated two-model review and the `CodeRabbit`,
`build-test`, `macos-test`, `claude-review`, and `scan` checks on the exact PR
head. A passing or skipped check does not replace review of the findings.
Re-run checks and review after every new commit. The `ci` workflow runs Linux
and macOS checks on pushes to both `next` and `main`.

Prepare the version and changelog on `next`, or on a short-lived
`release/vX.Y.Z` branch cut from `next` that carries only the changelog heading
and version bump. Promote the prepared branch with a squash PR to `main`.
Require the same exact-head reviews and checks on that PR, then wait for the checks on the
resulting `main` head before tagging. Branch rules are maintained separately;
do not weaken existing protections to make promotion pass.

## Release checks

1. On `next` (or the release branch described above), choose the release tag
   and update the hardcoded version in `cmd/nockguard/main.go`,
   `docs/ROADMAP.md`, and the heading in `CHANGELOG.md`. Build the CLI and run
   `scripts/check-release-version.sh vX.Y.Z <binary>`. Verify customer docs
   against the code that will ship, then promote through the release PR above.
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
5. Immediately after tagging, back-sync `main` into `next` as described below,
   before accepting more work into `next`.
6. A maintainer updates the Homebrew tap, then downloads each intended platform
   archive, checks its SHA256 against `SHA256SUMS`, and runs `nockguard version`
   plus the customer quickstart on a clean host before announcing the release.

## Post-release back-sync

Squash promotion leaves `next` without the new `main` commit as an ancestor.
Merge `origin/main` back into `next` after tagging so the following release PR
does not show already-released changes again. Do this before new, unreleased
work arrives on `next`; if it has already arrived, stop and reconcile that work
rather than replacing it with the release tree.

From a clean checkout, fetch both branches and create a temporary branch from
`origin/next`. Merge `origin/main` with `git merge --no-ff --no-commit origin/main`.
Resolve every conflict to main's version with `git checkout origin/main -- .`;
also stage any deletions needed to match main. Commit the result as a normal
merge commit. Never reset or force-push `next`.

Before pushing, compare `git rev-parse 'origin/main^{tree}'` with
`git rev-parse 'HEAD^{tree}'`. They must be equal. Confirm `origin/next` has not
advanced, then push the merge commit with `git push origin HEAD:next` through
the administrator bypass in the `next-batch-gate` ruleset. This release
back-sync is the one direct push to `next`; every other change arrives by PR.

Source: `.github/workflows/release-assets.yml`,
`scripts/build-release-assets.sh`, `scripts/check-release-version.sh`.
