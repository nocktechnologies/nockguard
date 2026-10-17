#!/usr/bin/env bash
# Print docs_only=true or docs_only=false for the CI change-detect step.
# Docs are any *.md file and anything under docs/. Pushes, an empty file list
# and a failed API call all print false, so the full suite runs.
# Usage: scripts/ci-docs-only.sh <pr-number>; needs GH_TOKEN and GITHUB_REPOSITORY.
set -uo pipefail

pr=${1:-}
if [ -z "$pr" ]; then
  echo "docs_only=false"
  exit 0
fi

if ! files=$(gh api --paginate "repos/$GITHUB_REPOSITORY/pulls/$pr/files" --jq '.[].filename'); then
  echo "::warning::could not list PR files; running the full suite" >&2
  echo "docs_only=false"
  exit 0
fi

if [ -n "$files" ] && ! grep -qvE '(\.md$|^docs/)' <<<"$files"; then
  echo "docs_only=true"
else
  echo "docs_only=false"
fi
