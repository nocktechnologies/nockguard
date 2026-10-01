#!/usr/bin/env bash
# Usage: check-release-version.sh <tag> <nockguard-binary>
# Fails unless the binary's `version` output is exactly "nockguard <tag>".
# The version string is hardcoded in cmd/nockguard/main.go, so a release whose
# tag was not bumped in code must not ship.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <tag> <nockguard-binary>" >&2
  exit 2
fi
tag=$1
bin=$2

got=$("$bin" version)
want="nockguard $tag"
if [ "$got" != "$want" ]; then
  echo "version mismatch: binary reports '$got', release tag wants '$want'" >&2
  exit 1
fi
echo "version ok: $got"
