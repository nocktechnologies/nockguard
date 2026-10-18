# NockGuard contributor notes

Read this before you start. Before you finish, add what changed, what bit you
and what is still open, and remove anything no longer true. Keep it short.

## What changed

- Release metadata was updated for v0.10.1.
- `AGENTS.md` indexes project documentation and CI checks its linked paths.

- 2026-10-17, Nock 11968: `ci.yml` skips the suite on docs-only PRs
  (`scripts/ci-docs-only.sh`); `build-test` then runs the path check and the
  tests that read repo Markdown. AGENTS.md and CONTRIBUTING.md now ask for
  focused tests plus lint locally, not the full suite.

## What bit us

- The path checker treats a backticked `/slash-command` as an absolute path
  and a backticked example file name as a missing file. Write slash commands
  without backticks and example files as a `<placeholder>`.

- Docs-only is judged on the whole PR file list, not the last commit, so a
  PR that once touched code keeps running the full suite. If you add a test
  that reads a Markdown file, add it to the `doc-pinned tests` step in
  `.github/workflows/ci.yml`.
  A rename or copy counts as docs only when both paths are docs;
  `scripts/ci-docs-only-test.sh` pins that and runs on every PR.

## Still open

None recorded.
