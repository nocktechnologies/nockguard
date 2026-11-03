# GitHub MCP server under Claude Code: no public repos, no deletes

Copy this folder, fill in four paths, and Claude Code talks to the GitHub MCP
server through NockGuard. The agent keeps every GitHub tool it uses for normal
work (issues, branches, files, pull requests), but it cannot create a
repository or delete one. Every call it makes, allowed or denied, lands in a
signed audit trail you check with one command.

## Why

In September 2026, researchers found that coding agents had exposed more than
13,000 internal images by pushing them to new public repos under developers'
personal accounts, because the GitHub CLI cannot attach images to a pull
request ([write-up](https://aviatrix.ai/threat-research-center/ai-coding-agents-exposed-13000-internal-images-github-2026/)).

## What it blocks

`policy.yaml` gives the `claude-code` agent `mode: allow` and denies two tools:

| Tool | Why |
|---|---|
| `create_repository` | The agent cannot make a public repo to park files in. |
| `delete_repository` | The agent cannot delete a repo. |

Visibility is the `private` argument of `create_repository`, and NockGuard
policy matches tool names, not argument values. So the policy denies repo
creation outright, private repos included. When you need a new repo, create it
yourself in the browser or with `gh repo create`, where you choose the
visibility. Denied tools are also hidden from the agent's tool list.

If your server version exposes a tool that changes an existing repo's
visibility, add its name to `deny`.

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

5. Restart Claude Code and run `/mcp`: the `github` server should be connected.
   Ask the agent to list your open pull requests, then ask it to create a
   public repo. The first works; the second is refused.

## Check the trail

```bash
nockguard verify --agent claude-code   # exit 0 and PROTECTED for a non-empty, fully checkpointed trail
nockguard wall --agent claude-code     # browse the decisions in the Live Wall
```

The trail records each decision and the tool name, never the arguments or the
token.

## What it does not cover

- Anything outside this MCP server. An agent with a shell can still run
  `gh repo create --public` or `git push` to a public remote. Limit the token's
  scopes, and use your organization's setting that restricts who can create
  public repositories.
- Public gists. `create_gist` is allowed here; add it to `deny` if your agents
  have no use for gists.

## Files

| File | What |
|---|---|
| `policy.yaml` | the policy: allow by default, deny the two tools above |
| `.mcp.json` | Claude Code config that runs the GitHub MCP server under `nockguard proxy` |
| `policy_test.go` | CI test: loads `policy.yaml` and checks the deny and allow verdicts |

Run the test from the repo root: `go test ./examples/...`
