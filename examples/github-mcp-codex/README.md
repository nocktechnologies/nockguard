# GitHub MCP server under Codex CLI: no repo creates, forks or deletes

Copy one config snippet and one policy file, fill in four paths, and Codex CLI
talks to the GitHub MCP server through NockGuard. The agent keeps the GitHub
tools it uses for normal work (issues, branches, files, pull requests), but it
cannot create, fork or delete a repository through that server. Every call it
makes, allowed or denied, lands in a signed audit trail you check with one
command.

This is the Codex CLI version of the
[Claude Code example](../github-mcp-claude-code/README.md): same server image,
same flags, same three denies. It covers the GitHub MCP server only. An agent
that also has a shell and a `gh` login can still create a repo; see
[What it does not cover](#what-it-does-not-cover).

## What it blocks

`policy.yaml` gives the `codex` agent `mode: allow` and denies three tools:

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

`config.toml` pins the server image to `ghcr.io/github/github-mcp-server:v2.0.3`.
That version has no tool that changes an existing repo's visibility. If you
move to a later version, check its tool list, and add any such tool to `deny`.

## Setup (5 minutes)

You need `nockguard` (`brew install nocktechnologies/tap/nockguard`), Docker,
Codex CLI, and a GitHub personal access token in `GITHUB_PERSONAL_ACCESS_TOKEN`
in the shell you start Codex from.

1. Create the signing key for this agent:

   ```bash
   nockguard keygen --agent codex   # writes ~/.nockguard/keys/codex.ed25519 and codex.pub
   ```

2. Copy `policy.yaml` somewhere stable, such as `~/.nockguard/github-policy.yaml`.

3. Collect the absolute paths for the config:

   ```bash
   command -v nockguard
   command -v docker
   printf '%s\n' "$PATH"
   ```

4. Add the `[mcp_servers.github]` table from `config.toml` to
   `~/.codex/config.toml`, or to `.codex/config.toml` in a trusted project.
   If you already have a `github` server there, replace it. Replace
   `<NOCKGUARD_PATH>` and `<DOCKER_PATH>` with the paths above, `<SHELL_PATH>`
   with the `PATH` value, and `<POLICY_PATH>` with the absolute path of your
   policy copy. `env_vars` tells Codex to forward
   `GITHUB_PERSONAL_ACCESS_TOKEN` from its own environment to the server, so
   the token never sits in the file. Codex starts the server with a short
   list of environment variables, so if your shell sets others the proxy or
   Docker needs, such as `DOCKER_HOST` or the `NOCKGUARD_AUDIT_*` and
   `NOCKGUARD_AGENT_CODEX_*` signing keys, add their names to `env_vars` too.

5. Pull the server image once, so the first start fits inside Codex's
   10-second MCP startup timeout:

   ```bash
   docker pull ghcr.io/github/github-mcp-server:v2.0.3
   ```

6. Check that Codex reads the entry:

   ```bash
   codex mcp get github
   ```

   The output shows `transport: stdio`, your nockguard path as `command`, the
   `proxy --upstream ...` args, and `GITHUB_PERSONAL_ACCESS_TOKEN` in `env`
   (masked).

7. Check the deny before you start Codex. This sends one `create_repository`
   call through the same policy, with `cat` standing in for the GitHub server,
   so nothing reaches GitHub even if the policy were wrong:

   ```bash
   printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_repository","arguments":{"name":"smoke-test","private":false}}}' \
     | nockguard proxy --upstream cat --agent codex --policy <POLICY_PATH>
   ```

   The reply is a JSON-RPC error, `tool "create_repository" denied by policy`,
   and the trail gets a row with `"tool":"create_repository","decision":"deny"`.

8. Start `codex` and run `/mcp`: the `github` server should be listed with its
   tools. Ask the agent to list your open pull requests. The three denied
   tools are not in its tool list.

## Check the trail

```bash
nockguard verify --agent codex   # exit 0 and PROTECTED for a non-empty, fully checkpointed trail
grep '"tool":"create_repository"' ~/.nockguard/logs/codex.audit.jsonl   # the deny from step 7
nockguard wall --agent codex     # browse the decisions in the Live Wall
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

## Config source

The `[mcp_servers.<name>]` keys used here (`command`, `args`, `env`,
`env_vars`) follow the Codex MCP docs at
<https://learn.chatgpt.com/docs/extend/mcp?surface=cli> (where
<https://developers.openai.com/codex/mcp> redirects), checked 2026-11-17. With codex-cli
0.160.0, `codex mcp get github` on this snippet (placeholders filled in) shows
the stdio command, the proxy args, and both environment entries.

## Files

| File | What |
|---|---|
| `policy.yaml` | the policy: allow by default, deny the three tools above |
| `config.toml` | Codex CLI config that runs the pinned GitHub MCP server under `nockguard proxy` |
| `policy_test.go` | CI test: loads `policy.yaml`, checks the deny and allow verdicts, and checks the `config.toml` entry |

Run the test from the repo root: `go test ./examples/...`
