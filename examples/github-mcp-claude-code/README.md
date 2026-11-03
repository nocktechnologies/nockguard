# GitHub MCP server under Claude Code: no repo creates, forks or deletes

Copy this folder, fill in four paths, and Claude Code talks to the GitHub MCP
server through NockGuard. The agent keeps the GitHub tools it uses for normal
work (issues, branches, files, pull requests), but it cannot create, fork or
delete a repository through that server. Every call it makes, allowed or
denied, lands in a signed audit trail you check with one command.

This covers the GitHub MCP server only. An agent that also has a shell and a
`gh` login can still create a repo; see [What it does not cover](#what-it-does-not-cover).

## Why

In September 2026, researchers found that coding agents had exposed more than
13,000 internal images by pushing them to new public repos under developers'
personal accounts, because the GitHub CLI cannot attach images to a pull
request ([write-up](https://aviatrix.ai/threat-research-center/ai-coding-agents-exposed-13000-internal-images-github-2026/)).
Those agents used the GitHub CLI in a shell, not the MCP server. This example
closes the same hole on the MCP side; the shell needs its own control.

## What it blocks

`policy.yaml` gives the `claude-code` agent `mode: allow` and denies three tools:

| Tool | Why |
|---|---|
| `create_repository` | The agent cannot make a public repo to park files in. |
| `fork_repository` | A fork of a public repo is public, so it is another way to get a new public repo. |
| `delete_repository` | The agent cannot delete a repo. |

Visibility is the `private` argument of `create_repository`, and NockGuard
policy matches tool names, not argument values. So the policy denies repo
creation outright, private repos included. When you need a new repo, create it
yourself, where you choose the visibility. Denied tools are also hidden from
the agent's tool list.

`.mcp.json` pins the server image to `ghcr.io/github/github-mcp-server:v2.0.3`.
That version has no tool that changes an existing repo's visibility. If you
move to a later version, check its tool list, and add any such tool to `deny`.

## Setup (5 minutes)

You need `nockguard` (`brew install nocktechnologies/tap/nockguard`), Docker,
and a GitHub personal access token in `GITHUB_PERSONAL_ACCESS_TOKEN`.

1. Create the signing key for this agent:

   ```bash
   nockguard keygen --agent claude-code   # writes ~/.nockguard/keys/claude-code.ed25519 and claude-code.pub
   ```

2. Copy `policy.yaml` somewhere stable, such as `~/.nockguard/github-policy.yaml`.

3. Collect the absolute paths for the config:

   ```bash
   command -v nockguard
   command -v docker
   printf '%s\n' "$PATH"
   ```

4. Copy `.mcp.json` into your project root, or merge its `github` entry into the
   one you have. Replace `<NOCKGUARD_PATH>` and `<DOCKER_PATH>` with the paths
   above, `<SHELL_PATH>` with the `PATH` value, and `<POLICY_PATH>` with the
   absolute path of your policy copy. Claude Code fills in
   `${GITHUB_PERSONAL_ACCESS_TOKEN}` from your environment, so the token never
   sits in the file.

5. Check the deny before you start Claude Code. This sends one
   `create_repository` call through the same policy, with `cat` standing in for
   the GitHub server, so nothing reaches GitHub even if the policy were wrong:

   ```bash
   printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_repository","arguments":{"name":"smoke-test","private":false}}}' \
     | nockguard proxy --upstream cat --agent claude-code --policy <POLICY_PATH>
   ```

   The reply is a JSON-RPC error, `tool "create_repository" denied by policy`,
   and the trail gets a row with `"tool":"create_repository","decision":"deny"`.

6. Restart Claude Code and run `/mcp`: the `github` server should be connected.
   Ask the agent to list your open pull requests. `create_repository`,
   `fork_repository` and `delete_repository` are not in its tool list.

## Check the trail

```bash
nockguard verify --agent claude-code   # exit 0 and PROTECTED for a non-empty, fully checkpointed trail
grep '"decision":"deny"' ~/.nockguard/logs/claude-code.audit.jsonl   # the smoke-check deny from step 5
nockguard wall --agent claude-code     # browse the decisions in the Live Wall
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

## Files

| File | What |
|---|---|
| `policy.yaml` | the policy: allow by default, deny the three tools above |
| `.mcp.json` | Claude Code config that runs the pinned GitHub MCP server under `nockguard proxy` |
| `policy_test.go` | CI test: loads `policy.yaml` and checks the deny and allow verdicts |

Run the test from the repo root: `go test ./examples/...`
