#!/bin/bash
# Builds a universal (Apple silicon + Intel) Dozor.app and packs it for a
# GitHub release into release/<version>/: a zip made with ditto (keeps the
# signature and extended attributes intact) and its SHA-256 checksum.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export VERSION="${VERSION:-0.0.1}"
export ARCHS="${ARCHS:-arm64 x86_64}"
OUT="$ROOT/release/$VERSION"
ZIP="Dozor-$VERSION-macos-universal.zip"

"$ROOT/Scripts/bundle.sh" release

rm -rf "$OUT"
mkdir -p "$OUT"
ditto -c -k --sequesterRsrc --keepParent "$ROOT/build/Dozor.app" "$OUT/$ZIP"
(cd "$OUT" && shasum -a 256 "$ZIP" > "$ZIP.sha256")

echo "packed $OUT/$ZIP"
cat "$OUT/$ZIP.sha256"
