# Warden Agent Template

A Claude Code agent that reads your NockGuard audit trail and keeps your fleet accountable.

## Deploy in 30 seconds

```bash
# Copy the template into any Claude Code project
cp templates/warden/CLAUDE.md /path/to/your/project/CLAUDE.md

# Open Claude Code in that directory — Warden is ready
cd /path/to/your/project
claude
```

## What it does

- Reads `~/.nockguard/logs/audit.jsonl` and surfaces violations
- Flags block events (injection/secret-exfil attempts) immediately
- Spots deny and ratelimit patterns that point to policy gaps
- Suggests minimal, concrete YAML policy changes
- Walks first-time setup (`nockguard init`)
- Explains what you see on the Live Wall (`nockguard-wall`)
- Verifies audit chain integrity

## Security skills (slash commands)

This template ships three beginner-facing slash commands. Deploy them alongside `CLAUDE.md`:

```bash
# Copy skills into your project
cp -r templates/warden/.claude /path/to/your/project/
```

Once deployed, invoke from Claude Code:

| Command | What it does |
|---------|-------------|
| `/threat-model` | Guided threat-modeling session — inventory agents, classify tools by risk, and produce a starting policy |
| `/vuln-scan` | Scan the live policy and audit trail for security gaps, ranked by severity |
| `/policy-lint` | Structural and logic lint of a policy file — catch errors before deploying |

Run `/policy-lint` after every policy edit. Run `/vuln-scan` periodically as agents are added or access patterns change.

## Requirements

- [NockGuard](https://github.com/nocktechnologies/nockguard) installed
- Claude Code (any plan)
- `jq` for audit log queries (optional but recommended)
- `python3` with `pyyaml` for `/policy-lint` checks (`pip install pyyaml`)
