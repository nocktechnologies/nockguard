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

## Requirements

- [NockGuard](https://github.com/nocktechnologies/nockguard) installed
- Claude Code (any plan)
- `jq` for audit log queries (optional but recommended)
