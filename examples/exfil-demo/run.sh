#!/usr/bin/env bash
# One-command poisoned-MCP-server exfil demo. Needs python3 and `nockguard` on PATH.
#   bash run.sh               protected: the starter policy blocks the exfil
#   bash run.sh --unprotected negative control: an allow-all policy lets it through
set -euo pipefail

policy=policy.yaml
case "${1:-}" in
  "") ;;
  --unprotected) policy=policy.unprotected.yaml ;;
  *) echo "usage: bash run.sh [--unprotected]" >&2; exit 2 ;;
esac

for bin in nockguard python3; do
  command -v "$bin" >/dev/null || { echo "error: $bin not found on PATH" >&2; exit 1; }
done

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Everything the demo writes lives under this temp dir. HOME points at it so
# nockguard's ~/.nockguard state never touches the real one.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
export HOME="$tmp"
NOCKGUARD_AUDIT_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
export NOCKGUARD_AUDIT_KEY
unset NOCKGUARD_AGENT_DEMO_ED25519_KEY

echo "$(nockguard version)  policy: $policy"
echo "=================================================="
cd "$here"
python3 agent_script.py "$here/$policy"

echo
echo "Verifying the audit trail (nockguard verify):"
nockguard verify --key-env NOCKGUARD_AUDIT_KEY --audit "$tmp/.nockguard/logs/exfil-demo.audit.jsonl"
echo "(The verdict is about the trail: unedited, in order. It does not say the policy was any good.)"
