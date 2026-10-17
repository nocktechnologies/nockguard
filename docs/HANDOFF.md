# NockGuard pod notes

Read this before you start. Before you finish, add what changed, what bit you
and what is still open, and remove anything no longer true. Keep it short.

## What changed

- 2026-10-17, Nock 11936: `AGENTS.md` rewritten as the agent index; CI now
  runs `scripts/check-agents-paths.py`. Landed on `main` as a docs-only
  exception; it reaches `next` at the next back-sync.

## What bit us

- The path checker treats a backticked `/slash-command` as an absolute path
  and a backticked example file name as a missing file. Write slash commands
  without backticks and example files as a `<placeholder>`.

## Still open

- `docs/runbooks/release.md` links to `CLAUDE.md#build-and-test`, which no
  longer resolves because `CLAUDE.md` only imports `AGENTS.md`. Point it at
  `AGENTS.md#build-and-test` when the release runbook is next edited on `next`.
