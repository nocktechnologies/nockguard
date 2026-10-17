# NockGuard pod notes

Read this before you start. Before you finish, add what changed, what bit you
and what is still open, and remove anything no longer true. Keep it short.

## What changed

- 2026-10-17: Prepared v0.10.1 metadata from `next` commit
  `647b8ec97f70eafd2123090309fc2038c9d637ea`. Cleanup PR #185 is included;
  the later batch changes are contributor/release docs and a CI path check.
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

- v0.10.1 needs maintainer promotion, exact-main checks, the Linux asset dry
  run, tagging and distribution checks. Keep `next` frozen through the checked
  main-to-next back-sync in `docs/runbooks/release.md`.
