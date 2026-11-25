#!/bin/sh
# Package a built ezcrypt binary for release.
# Usage: install/package.sh <target> <outdir>
# Expects `cargo build --locked --release -p ezcrypt-cli --target <target>`
# to have run. The target dir comes from CARGO_TARGET_DIR, else from cargo
# itself (the repo's .cargo/config.toml relocates it to .build/rust).
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <target> <outdir>" >&2
  exit 2
fi
target=$1
outdir=$2
if [ -n "${CARGO_TARGET_DIR:-}" ]; then
  tdir=$CARGO_TARGET_DIR
else
  # Pull "target_directory" out of the metadata JSON without needing jq or
  # python; JSON escapes Windows backslashes, so turn them into slashes.
  tdir=$(cargo metadata --no-deps --format-version 1 |
    sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p' | sed 's/\\\\/\//g')
  [ -n "$tdir" ] || { echo "cannot determine cargo target directory" >&2; exit 1; }
fi

mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)

case "$target" in
  *-windows-*)
    bin=$tdir/$target/release/ezcrypt.exe
    [ -f "$bin" ] || { echo "missing $bin" >&2; exit 1; }
    archive=$outdir/ezcrypt-$target.zip
    rm -f "$archive"
    stage=$(mktemp -d)
    trap 'rm -rf "$stage"' EXIT
    cp "$bin" "$stage/ezcrypt.exe"
    if command -v 7z >/dev/null 2>&1; then
      (cd "$stage" && 7z a -tzip "$archive" ezcrypt.exe >/dev/null)
    else
      (cd "$stage" && zip -q "$archive" ezcrypt.exe)
    fi
    ;;
  *)
    bin=$tdir/$target/release/ezcrypt
    [ -f "$bin" ] || { echo "missing $bin" >&2; exit 1; }
    archive=$outdir/ezcrypt-$target.tar.gz
    stage=$(mktemp -d)
    trap 'rm -rf "$stage"' EXIT
    cp "$bin" "$stage/ezcrypt"
    chmod 755 "$stage/ezcrypt"
    tar -C "$stage" -czf "$archive" ezcrypt
    ;;
esac
echo "$archive"
