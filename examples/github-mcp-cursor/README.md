# GitHub MCP server under Cursor: no repo creates, forks or deletes

Copy one `mcp.json` entry and one policy file, fill in four paths, and Cursor
talks to the GitHub MCP server through NockGuard. The agent keeps the GitHub
tools it uses for normal work (issues, branches, files, pull requests), but it
cannot create, fork or delete a repository through that server. Every call it
makes, allowed or denied, lands in a signed audit trail you check with one
command.

This is the Cursor version of the
[Claude Code example](../github-mcp-claude-code/README.md) and the
[Codex CLI example](../github-mcp-codex/README.md): same server image, same
flags, same three denies. It covers the GitHub MCP server only. An agent that
also has a shell and a `gh` login can still create a repo; see
[What it does not cover](#what-it-does-not-cover).

## What it blocks

`policy.yaml` gives the `cursor` agent `mode: allow` and denies three tools:

| Tool | Why |
|---|---|
| `create_repository` | The agent cannot make a public repo to park files in. |
| `fork_repository` | A fork of a public repo is public. |
| `delete_repository` | The agent cannot delete a repo. |

Visibility is the `private` argument of `create_repository`, and NockGuard
policy matches tool names, not argument values. So the policy denies repo
creation outright, private repos included. When you need a new repo, create it
yourself, where you choose the visibility. Denied tools are also hidden from
the agent's tool list.

`mcp.json` pins the server image to `ghcr.io/github/github-mcp-server:v2.0.3`.
That version has no tool that changes an existing repo's visibility. If you
move to a later version, check its tool list, and add any such tool to `deny`.

## Setup (5 minutes)

You need `nockguard` (`brew install nocktechnologies/tap/nockguard`), Docker,
Cursor, and a GitHub personal access token in `GITHUB_PERSONAL_ACCESS_TOKEN`
in the environment Cursor runs in. Starting Cursor from that shell (`cursor .`)
gives it the variable.

1. Create the signing key for this agent:

   ```bash
   nockguard keygen --agent cursor   # writes ~/.nockguard/keys/cursor.ed25519 and cursor.pub
   ```

2. Copy `policy.yaml` somewhere stable, such as `~/.nockguard/github-policy.yaml`.

3. Collect the absolute paths for the config:

   ```bash
   command -v nockguard
   command -v docker
   printf '%s\n' "$PATH"
   ```

4. Copy `mcp.json` to `.cursor/mcp.json` in your project, or to
   `~/.cursor/mcp.json` for every project. If the file exists, merge in the
   `github` entry, replacing any `github` server already there. Replace
   `<NOCKGUARD_PATH>` and `<DOCKER_PATH>` with the paths above, `<SHELL_PATH>`
   with the `PATH` value, and `<POLICY_PATH>` with the absolute path of your
   policy copy. Cursor fills in
   `${env:GITHUB_PERSONAL_ACCESS_TOKEN}` from its own environment, so the token
   never sits in the file. If the proxy or Docker needs other variables from
   your shell, such as `DOCKER_HOST` or the `NOCKGUARD_AUDIT_*` and
   `NOCKGUARD_AGENT_CURSOR_*` signing keys, add them to `env` the same way.

5. Pull the server image once, so the first start is not the image download:

   ```bash
   docker pull ghcr.io/github/github-mcp-server:v2.0.3
   ```

6. Check the deny before you start Cursor. This sends one `create_repository`
   call through the same policy, with `cat` standing in for the GitHub server,
   so nothing reaches GitHub even if the policy were wrong:

   ```bash
   printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_repository","arguments":{"name":"smoke-test","private":false}}}' \
     | nockguard proxy --upstream cat --agent cursor --policy <POLICY_PATH>
   ```

   The reply is a JSON-RPC error, `tool "create_repository" denied by policy`,
   and the trail gets a row with `"tool":"create_repository","decision":"deny"`.

7. Open Cursor and find the `github` server under **Customize** in the
   sidebar, with its tools under **Available Tools**. If it does not connect,
   open the Output panel and pick **MCP Logs**. Ask the agent to list your open
   pull requests. The three denied tools are not in its tool list.

   With the Cursor CLI, run these from the project directory instead:

   ```bash
   cursor-agent mcp enable github       # approve the server on first use
   cursor-agent mcp list-tools github   # the three denied tools are absent
   ```

## Check the trail

```bash
nockguard verify --agent cursor   # exit 0 and PROTECTED for a non-empty, fully checkpointed trail
grep '"tool":"create_repository"' ~/.nockguard/logs/cursor.audit.jsonl   # the deny from step 6
nockguard wall --agent cursor     # browse the decisions in the Live Wall
```

The trail records each decision and the tool name, never the arguments or the
token.

## What it does not cover

- A shell. NockGuard blocks these GitHub MCP tools; it does not see commands
  the agent runs in a terminal. An agent with a shell and a `gh` login can
  still run `gh repo create --public`. That needs a separate control: a token
  that cannot create repos, or a shell fence such as
  [NockLock](https://github.com/nocktechnologies/nocklock). For fine-grained
  tokens, GitHub lists creating a repo under the "Administration" and
  "Repository creation" write permissions
  ([permissions reference](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens)).
- Pushes to an existing public repo. The file and branch tools stay allowed,
  so the agent can still write files to any public repo the token can push to.
  Give the token access only to the repos the agent works on.
- Public gists. `create_gist` is allowed here; add it to `deny` if your agents
  have no use for gists.
- Cursor Cloud Agents. They do not read `~/.cursor/mcp.json`; this setup runs
  the proxy on your machine.

## Config source

The config paths (`.cursor/mcp.json` per project, `~/.cursor/mcp.json`
global), the `mcpServers.<name>` keys used here (`type`, `command`, `args`,
`env`) and the `${env:NAME}` interpolation follow the Cursor MCP docs at
<https://cursor.com/docs/context/mcp>, read 2026-11-24. The stdio table there
lists `type: "stdio"` as required. The CLI commands follow
<https://cursor.com/docs/cli/mcp>, read the same day; the CLI uses the same
`mcp.json` as the editor. With Cursor CLI 2026.10.01-e373342,
`cursor-agent mcp list-tools github` on this snippet (placeholders filled in)
lists the tools without the three denied ones, and
`nockguard verify --agent cursor` reports PROTECTED.

## Files

| File | What |
|---|---|
| `policy.yaml` | the policy: allow by default, deny the three tools above |
| `mcp.json` | Cursor MCP entry that runs the pinned GitHub MCP server under `nockguard proxy` |
| `policy_test.go` | CI test: loads `policy.yaml`, checks the deny and allow verdicts, and checks the `mcp.json` entry |

Run the test from the repo root: `go test ./examples/...`
