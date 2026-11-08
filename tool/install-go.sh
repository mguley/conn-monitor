#!/usr/bin/env bash

set -euo pipefail

repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
version=1.27.3

case "$(uname -m)" in
  x86_64)
    arch=amd64
    expected=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40
    ;;
  aarch64|arm64)
    arch=arm64
    expected=a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49
    ;;
  *)
    echo "This script supports Linux amd64 and arm64." >&2
    exit 1
    ;;
esac

dest="$repo/.tools/go$version"
if [[ -e "$dest" ]]; then
  echo "$dest already exists; inspect it or use its go/bin/go." >&2
  exit 1
fi

mkdir -p "$repo/.tools"

stage=$(mktemp -d "$repo/.tools/go-download.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT

archive="$stage/go.tar.gz"
curl --fail --location --retry 3 --proto '=https' --tlsv1.2 "https://go.dev/dl/go$version.linux-$arch.tar.gz" -o "$archive"

echo "Verifying Go $version ($arch) SHA-256 checksum..."
printf '%s  %s\n' "$expected" "$archive" | sha256sum --check

tar -xzf "$archive" -C "$stage"
mkdir "$dest"
mv "$stage/go" "$dest/go"

"$dest/go/bin/go" version
printf 'Toolchain installed. In your current shell run:\nexport PATH="%s/go/bin:$PATH"\n' "$dest"