#!/usr/bin/env bash

set -euo pipefail

repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
version=2.15.0

if [[ "$(uname -s)" != Linux ]]; then
  echo "This script supports Linux only." >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64)
    arch=amd64
    expected=9b7fe6a6bf6334b98decf8d86b11415ea7889afdabdd1959fdce23af2a9ebcea
    ;;
  aarch64|arm64)
    arch=arm64
    expected=b4d8f17068b35ee6060cc2f69a16fb48740d706fbba81661c318649c114a6998
    ;;
  *)
    echo "This script supports Linux amd64 and arm64." >&2
    exit 1
    ;;
esac

dest="$repo/.tools/golangci-lint$version"
if [[ -e "$dest" || -L "$dest" ]]; then
  echo "$dest already exists; inspect it or use its bin/golangci-lint." >&2
  exit 1
fi

mkdir -p "$repo/.tools"

stage=$(mktemp -d "$repo/.tools/golangci-lint-download.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT

release="golangci-lint-$version-linux-$arch"
archive="$stage/$release.tar.gz"

curl --fail --location --retry 3 --proto '=https' --tlsv1.2 \
  "https://github.com/golangci/golangci-lint/releases/download/v$version/$release.tar.gz" \
  -o "$archive"

echo "Verifying golangci-lint $version ($arch) SHA-256 checksum..."
printf '%s  %s\n' "$expected" "$archive" | sha256sum --check

tar -xzf "$archive" -C "$stage" "$release/golangci-lint"

mkdir -p "$stage/install/bin"
install -m 0755 "$stage/$release/golangci-lint" "$stage/install/bin/golangci-lint"

mv -T -- "$stage/install" "$dest"

"$dest/bin/golangci-lint" version
printf 'Linter installed. In your current shell run:\nexport PATH="%s/bin:$PATH"\n' "$dest"
