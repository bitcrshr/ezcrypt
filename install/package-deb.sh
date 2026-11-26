#!/bin/sh
# Build a .deb from a packaged Linux release archive, so the package holds
# exactly the binary that ships in the archive.
# Usage: install/package-deb.sh <ezcrypt-TARGET.tar.gz> <version> <outdir>
# Needs dpkg-deb 1.19 or newer (for --root-owner-group).
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <ezcrypt-TARGET.tar.gz> <version> <outdir>" >&2
  exit 2
fi
archive=$1
version=$2
outdir=$3

case "$(basename "$archive")" in
  ezcrypt-x86_64-unknown-linux-musl.tar.gz) arch=amd64 ;;
  ezcrypt-aarch64-unknown-linux-musl.tar.gz) arch=arm64 ;;
  *) echo "not a Linux release archive: $archive" >&2; exit 2 ;;
esac

# Debian sorts '~' before everything, so 0.2.0~rc1 comes before 0.2.0, as
# semver's 0.2.0-rc1 does.
debversion=$(printf '%s' "$version" | tr - '~')
case "$debversion" in
  '' | [!0-9]* | *[!A-Za-z0-9.+~]*)
    echo "invalid version: '$version' (expected e.g. 0.2.0 or 0.2.0-rc1)" >&2
    exit 2
    ;;
esac

repo=$(cd "$(dirname "$0")/.." && pwd)
holder=$(sed -n 's/^Copyright (c) //p' "$repo/LICENSE")
[ -n "$holder" ] || { echo "no copyright line in LICENSE" >&2; exit 1; }
name=${holder#* } # "2026 Chandler Davis" -> "Chandler Davis"

mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
root=$stage/root
mkdir -p "$root/DEBIAN" "$root/usr/bin" "$root/usr/share/doc/ezcrypt"

tar -xzf "$archive" -C "$root/usr/bin" ezcrypt
chmod 0755 "$root/usr/bin/ezcrypt"

{
  echo 'Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/'
  echo 'Upstream-Name: ezcrypt'
  echo 'Source: https://github.com/bitcrshr/ezcrypt'
  echo
  echo 'Files: *'
  echo "Copyright: $holder"
  echo 'License: Expat'
  sed -e 's/^$/./' -e 's/^/ /' "$repo/LICENSE"
} >"$root/usr/share/doc/ezcrypt/copyright"
chmod 0644 "$root/usr/share/doc/ezcrypt/copyright"

size=$(du -sk "$root/usr" | cut -f1)
# `enroll` offers ssh-keygen when no key exists; `trust` configures sshd.
cat >"$root/DEBIAN/control" <<EOF
Package: ezcrypt
Version: $debversion
Architecture: $arch
Maintainer: $name <12220125+bitcrshr@users.noreply.github.com>
Installed-Size: $size
Recommends: openssh-client
Suggests: openssh-server
Section: admin
Priority: optional
Homepage: https://github.com/bitcrshr/ezcrypt
Description: Use your iPhone as an SSH certificate authority
 ezcrypt pairs with the ezcrypt iPhone app through a QR code.
 "ezcrypt enroll" gets an SSH user certificate for your key from the
 phone, and "sudo ezcrypt trust" makes sshd trust the phone's user CA.
EOF

out=$outdir/ezcrypt-$arch.deb
# xz rather than dpkg's newer zstd default, so older dpkg can read it.
dpkg-deb --root-owner-group -Zxz --build "$root" "$out" >/dev/null
echo "$out"
