#!/bin/sh
# ezcrypt installer for Linux and macOS.
#   curl -fsSL https://github.com/bitcrshr/ezcrypt/releases/latest/download/install.sh | sh
# Set EZCRYPT_BASE_URL to install from somewhere other than the latest release.
set -eu

base_url=${EZCRYPT_BASE_URL:-https://github.com/bitcrshr/ezcrypt/releases/latest/download}

die() {
  echo "ezcrypt install: $*" >&2
  exit 1
}

os=$(uname -s)
arch=$(uname -m)
case "$os/$arch" in
  Linux/x86_64) target=x86_64-unknown-linux-musl ;;
  Linux/aarch64 | Linux/arm64) target=aarch64-unknown-linux-musl ;;
  Darwin/arm64) target=aarch64-apple-darwin ;;
  Darwin/x86_64) die "Intel Macs are not supported; ezcrypt ships for Apple silicon only" ;;
  *) die "unsupported platform: $os $arch" ;;
esac

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  die "curl or wget is required"
fi

archive=ezcrypt-$target.tar.gz
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Downloading $archive"
fetch "$base_url/$archive" "$tmp/$archive" || die "download failed: $base_url/$archive"
fetch "$base_url/SHA256SUMS" "$tmp/SHA256SUMS" || die "download failed: $base_url/SHA256SUMS"

# Keep only this archive's line, so other files in SHA256SUMS need not exist.
grep "  $archive\$" "$tmp/SHA256SUMS" >"$tmp/check" || die "$archive is not listed in SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
  verify() { sha256sum -c check >/dev/null 2>&1; }
elif command -v shasum >/dev/null 2>&1; then
  verify() { shasum -a 256 -c check >/dev/null 2>&1; }
else
  die "sha256sum or shasum is required"
fi
(cd "$tmp" && verify) || die "checksum mismatch for $archive"

tar -xzf "$tmp/$archive" -C "$tmp" ezcrypt
"$tmp/ezcrypt" --version >/dev/null || die "downloaded binary does not run on this system"

if [ "$(id -u)" -eq 0 ]; then
  dest=/usr/local/bin
else
  dest=$HOME/.local/bin
fi
mkdir -p "$dest"
install -m 755 "$tmp/ezcrypt" "$dest/ezcrypt"

case ":$PATH:" in
  *":$dest:"*) ;;
  *) echo "Note: $dest is not on your PATH. Add it, for example:"
     echo "  export PATH=\"$dest:\$PATH\"" ;;
esac

echo "Installed to $dest/ezcrypt"
"$dest/ezcrypt" --version
