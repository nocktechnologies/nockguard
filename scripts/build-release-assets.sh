#!/usr/bin/env bash
# Usage: build-release-assets.sh <tag> <outdir>
# Builds nockguard for four targets into <outdir>/nockguard_<version>_<os>_<arch>.tar.gz
# and writes <outdir>/SHA256SUMS. <version> is the tag without its leading "v".
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <tag> <outdir>" >&2
  exit 2
fi
tag=$1
out=$2
if ! [[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "refusing tag '$tag': expected vMAJOR.MINOR.PATCH[-prerelease]" >&2
  exit 1
fi
version=${tag#v}

mkdir -p "$out"
out=$(cd "$out" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

export CGO_ENABLED=0
archives=()
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  os=${target%/*}
  arch=${target#*/}
  dir="$stage/$os-$arch"
  mkdir -p "$dir"
  GOOS=$os GOARCH=$arch go build -trimpath -o "$dir/nockguard" ./cmd/nockguard

  tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@0 \
    -C "$dir" -cf - nockguard | gzip -n >"$out/nockguard_${version}_${os}_${arch}.tar.gz"
  archives+=("nockguard_${version}_${os}_${arch}.tar.gz")
done

(cd "$out" && sha256sum "${archives[@]}" >SHA256SUMS && sha256sum -c SHA256SUMS)
