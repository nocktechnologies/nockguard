#!/usr/bin/env bash
# Tests scripts/ci-docs-only.sh against fixture PR file lists. A stub gh runs
# the script's own --jq filter over each fixture with jq.
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/ci-docs-only.sh"
stub=$(mktemp -d)
trap 'rm -rf "$stub"' EXIT
cat >"$stub/gh" <<'STUB'
#!/usr/bin/env bash
[ -n "${FIXTURE:-}" ] || exit 1
while [ $# -gt 0 ]; do
  if [ "$1" = --jq ]; then jq -r "$2" <<<"$FIXTURE"; exit; fi
  shift
done
exit 1
STUB
chmod +x "$stub/gh"
export PATH="$stub:$PATH" GITHUB_REPOSITORY=o/r

failed=0
check() {
  local name=$1 want=$2 fixture=$3 pr=${4-1} got
  got=$(FIXTURE=$fixture "$script" "$pr" 2>/dev/null)
  if [ "$got" = "docs_only=$want" ]; then
    echo "ok   $name"
  else
    echo "FAIL $name: got $got, want docs_only=$want"
    failed=1
  fi
}

check "docs edit" true '[{"filename":"docs/a.md","status":"modified"},{"filename":"README.md","status":"modified"}]'
check "code edit" false '[{"filename":"docs/a.md","status":"modified"},{"filename":"cmd/x.go","status":"modified"}]'
check "code renamed into docs/" false '[{"filename":"docs/foo.go","previous_filename":"foo.go","status":"renamed"}]'
check "code renamed to .md" false '[{"filename":"foo.md","previous_filename":"foo.go","status":"renamed"}]'
check "docs renamed out of docs/" false '[{"filename":"foo.txt","previous_filename":"docs/foo.txt","status":"renamed"}]'
check "docs to docs rename" true '[{"filename":"docs/new.md","previous_filename":"docs/old.md","status":"renamed"}]'
check "code copied into docs/" false '[{"filename":"docs/foo.go","previous_filename":"foo.go","status":"copied"}]'
check "docs to docs copy" true '[{"filename":"docs/b.md","previous_filename":"docs/a.md","status":"copied"}]'
check "empty file list" false '[]'
check "API failure" false ''
check "push (no PR number)" false '[{"filename":"docs/a.md"}]' ''

exit $failed
