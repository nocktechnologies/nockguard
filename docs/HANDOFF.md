# NockGuard pod notes

Read this before you start. Before you finish, add what changed, what bit you
and what is still open, and remove anything no longer true. Keep it short.

## What changed

- 2026-10-17, Nock 11936: `AGENTS.md` rewritten as the agent index; CI now
  runs `scripts/check-agents-paths.py`. `docs/runbooks/release.md` now links
  its CI checks to `AGENTS.md#build-and-test`.

## What bit us

- PRs target `next`, not `main`; the first cut of Nock 11936 opened against
  `main` and had to be rebased. Check `docs/runbooks/release.md` before
  picking a base.
- The path checker treats a backticked `/slash-command` as an absolute path
  and a backticked example file name as a missing file. Write slash commands
  without backticks and example files as a `<placeholder>`.

## Still open

- Nothing from Nock 11936.
