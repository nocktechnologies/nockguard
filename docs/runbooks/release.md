# Release

## Change promotion

Keep each PR focused on one issue or internal tracking card and target `next`.
Maintainers gate the automated two-model review and the `CodeRabbit`,
`build-test`, `macos-test`, `claude-review`, and `scan` checks on the exact PR
head. A passing or skipped check does not replace review of the findings.
Re-run checks and review after every new commit. The `ci` workflow runs Linux
and macOS checks on pushes to both `next` and `main`.

Prepare the version and changelog on `next`, or on a short-lived
`release/vX.Y.Z` branch cut from `next` that carries only the release metadata
listed in step 1. Freeze `next` when release preparation starts: before
preparing metadata directly on `next`, or before cutting a release branch.
Keep the freeze through the post-release `main`-to-`next` back-sync. During the freeze, only Mira-gated
release-fix card PRs may merge into `next`; a maintainer must incorporate each
fix into the release candidate and rerun its exact-head review and checks before
promotion. No builder merges into `next` during the freeze. Promote the prepared
branch with a squash PR to `main`. Before promotion, record in the release PR
body the full `origin/next` commit SHA included in the final candidate. Fetch
with `git fetch origin`. Set `release_candidate_head` to the full head SHA of
the gated release PR, then require this check to exit zero:

```bash
git merge-base --is-ancestor origin/next "$release_candidate_head"
```

Stop on a nonzero exit; merge any missing release fixes into the candidate and
repeat its gate before proceeding. After this check, record the full SHA from
`git rev-parse origin/next`. After every incorporated release fix or metadata
change on `next`, repeat the fetch, set `release_candidate_head` to the new
gated release PR head, rerun the ancestry check, and then record the full SHA.
Call this recorded commit `release_next_head` in the steps below.
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

From a clean checkout, fetch both branches. Set `release_next_head` to the
recorded full SHA from the gated release PR, not an abbreviation. **Before
creating the merge or
replacing any files**, check:

```bash
git log --oneline "$release_next_head"..origin/next
test "$(git rev-parse origin/next)" = "$release_next_head"
```

The log must be empty and the equality check must pass. If the record is
missing, next differs, or any command fails, stop without merging, replacing
files or pushing. A maintainer must reconcile that work through a reviewed path.

Only after this check, create a temporary branch from `origin/next`. Merge
`origin/main` with `git merge --no-ff --no-commit origin/main`. Resolve conflicts
to main's version from the repository root with `git checkout origin/main -- :/`;
also stage any deletions needed to match main. Commit as a normal merge commit.
Never reset or force-push `next`.

Compare `git rev-parse 'origin/main^{tree}'` with `git rev-parse 'HEAD^{tree}'`.
They must be equal. This checks the merge result only; it does not detect
unreleased work, which is why the earlier commit check is mandatory. Fetch
`next` again and repeat the equality check against `release_next_head` before
pushing. If it advanced, stop. Otherwise push with `git push origin HEAD:next`
through the administrator bypass in the `next-batch-gate` ruleset. A normal
push will reject a concurrent non-fast-forward update; never override that
rejection. This release back-sync is the one direct push to `next`; every other
change arrives by PR.

Source: `.github/workflows/release-assets.yml`,
`scripts/build-release-assets.sh`, `scripts/check-release-version.sh`.
