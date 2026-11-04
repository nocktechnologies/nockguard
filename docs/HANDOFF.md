# NockGuard contributor notes

Read this before you start. Before you finish, add what changed, what bit you
and what is still open, and remove anything no longer true. Keep it short.

## What changed

- 2026-11-04: A missing Guard trail is no longer shown as an empty feed.
  `trailMissing` in `cmd/nockguard-wall/main.go` drives a startup warning and
  the `/context` `trailExists` field; the page swaps its empty-view heading.
  Open: the page reads `/context` once, so after the file appears the
  heading stays until the first row renders.

- 2026-11-04: The Wall's empty view shows installed commands, names the
  watched Guard trail and fills in the `--agent` name, read from the
  `/context` agent label before " (". A filter that hides every row shows a
  no-match line, toggled in `applyFilters`. Open: a Wall started without
  `--agent` watches the shared trail, while the suggested `proxy --agent`
  command writes that agent's own trail.

- 2026-10-28: The Wall text filter (browser `rowMatches`, server `matches`)
  also matches the decision reason. The PROOF export keeps its own
  agent-and-tool text filter in `internal/audit/export.go`, which the offline
  verifier re-applies to every row.

- 2026-10-22: The README default policy now uses `mode: deny`. Blocking claims
  name unapproved MCP tool calls, distinguish enforcement from observe/shadow
  checks and retain the separate egress-proxy scope.

- Release metadata was updated for v0.12.0.
- `AGENTS.md` indexes project documentation and CI checks its linked paths.

- 2026-10-17: `ci.yml` skips the suite on docs-only PRs
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

- A 2 GiB `prlimit --as` cap makes the Go runtime fault at startup
  (`runtime: unknown pc`) before any test runs, so it looks like a crash
  rather than a test failure. `go test ./cmd/nockguard/` needs about 4 GiB.

## Still open

- v0.12.0 release: `next` stays frozen from the release-prep merge until
  the post-release back-sync of `main`. Only maintainer-approved release-fix
  PRs merge during the freeze.
- PROOF text filter: a query found only in a reason shows rows on the Wall
  and in CSV/JSON but not in PROOF. Matching the reason there needs a new
  export schema version so older verifiers fail closed on it.
