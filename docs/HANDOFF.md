# NockGuard contributor notes

Read this before you start. Before you finish, add what changed, what bit you
and what is still open, and remove anything no longer true. Keep it short.

## What changed

- 2026-11-25: The Live Wall shows a read-only "Needs you" line for calls held
  for approval, from `GET /pending` (agent, tool, wait time) polled every 5 s;
  `/pulse` `pending` is the same count. The Wall calls
  `approval.ListPending` on `approval.DefaultLocalDir()`, like
  `nockguard approvals list`. A missing approvals directory reads as zero held
  calls; one that fails the owner/mode check, or a `DefaultLocalDir` error
  (kept in `broker.approvalsDirErr`), is a 503 and `pendingError`, never
  zero. The row list is height-capped and scrolls; `checkPending` keeps a
  request sequence so a stale response is dropped. `--demo` leaves the directory unset. Only the local approver's holds
  appear. The browser test harness
  in `cmd/nockguard-wall/index.test.js` gained `replaceChildren`; its `esc`
  stub does not escape, so a source assertion there pins `esc()` on the agent
  and tool. `ListPending` dials each socket in turn (2 s connect, 10 s
  exchange), so an unresponsive proxy slows `/pending` and `/pulse`;
  `nockguard approvals prune` clears dead sockets.

- 2026-11-24: `examples/github-mcp-cursor/` adds the GitHub MCP wrap for
  Cursor. Cursor interpolates `${env:NAME}`, not plain `${NAME}`;
  `policy_test.go` pins that for the token. Approving the server in the
  Cursor CLI (`cursor-agent mcp enable github`) is tied to the entry's
  content, so re-run it after editing the entry.

- 2026-11-20: Release metadata now names v0.12.2. The changelog groups the
  Codex CLI GitHub MCP example and the Live Wall decision labels in this
  release; the CLI version and roadmap agree.

- 2026-11-18: Live Wall decision badges and filter options now show
  plain-language labels. Badge hover text explains the recorded event. Raw
  decision values remain in filtering, exports, proofs and trail data;
  unfamiliar values display as recorded. The mapping lives in
  `cmd/nockguard-wall/index.html` and browser coverage in its adjacent test.
  Method, policy, Guard and rate-limit stops use distinct labels; approval
  labels name the recorded step without claiming who approved it. Lock fence
  rows reuse `allow` and `block`, so their hover text checks the row source.
  The demo screenshot was reviewed on the PR and is not tracked in the repo.

- 2026-11-11: The Live Wall caps future decision timestamps at the browser's
  current time when updating "Last decision." Clock skew no longer hides a
  decision, and a far-future row ages normally after it arrives.

- 2026-11-11: Release metadata now names v0.12.1. The changelog groups the
  Go 1.27.4 security toolchain update and Live Wall decision age in this
  release; the CLI version and roadmap agree.

- 2026-11-11: The Live Wall evidence section now shows the latest decision's
  age and local time. The age refreshes every 30 seconds, includes filtered
  rows, and labels demo data as synthetic. Invalid timestamps are ignored.

- 2026-11-11: `go.mod` now requires Go 1.27.4 for GO-2026-6859 in
  `net/http`. CI and release builds derive their Go version from `go.mod`;
  the reported `MaxBytesReader` trigger is not called by project source.

- 2026-11-04: A missing Guard trail is no longer shown as an empty feed.
  `trailMissing` in `cmd/nockguard-wall/main.go` drives a startup warning and
  the `/context` `trailExists` field; the page swaps its empty-view heading.
  Open: the page reads `/context` once, so after the file appears the
  heading stays until the first row renders.

- 2026-11-04: The Wall's empty view shows installed commands, names the
  watched Guard trail and fills in the `--agent` name, read from the
  `/context` agent label before " (". Without `--agent` the Wall watches the
  shared trail, so the view pairs the proxy command with
  `nockguard wall --agent <name>` (`#empty-wall`). An `--agent` Wall shows it
  too: with `--audit` it may watch another trail. Open: that pairing holds
  for zero-config `proxy`; with `--policy` and no per-agent key the proxy
  writes the policy-wide trail (`AuditorForAgent` in `internal/policy/`). A filter that hides every
  row shows a no-match line, toggled in `applyFilters`. `render` removes
  `#empty` on the first row, which can beat `/context`; the `/context`
  handler skips the empty-state block once `empty` is null.

- 2026-10-28: The Wall text filter (browser `rowMatches`, server `matches`)
  also matches the decision reason. The PROOF export keeps its own
  agent-and-tool text filter in `internal/audit/export.go`, which the offline
  verifier re-applies to every row.

- 2026-10-22: The README default policy now uses `mode: deny`. Blocking claims
  name unapproved MCP tool calls, distinguish enforcement from observe/shadow
  checks and retain the separate egress-proxy scope.

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

- v0.12.2 release packaging and publication are pending.
- PROOF text filter: a query found only in a reason shows rows on the Wall
  and in CSV/JSON but not in PROOF. Matching the reason there needs a new
  export schema version so older verifiers fail closed on it.
