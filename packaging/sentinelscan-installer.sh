#!/bin/sh
# SentinelScan installer: downloads the release archive, verifies its
# SHA-256 checksum, and installs the binary. Never runs a scan.
#
# Usage:
#   curl -LsSf https://github.com/Devraj192/sentinel-scanner/releases/download/v2.0.0/sentinelscan-installer.sh | sh
#   VERSION=2.0.0 PREFIX="$HOME/.local" sh sentinelscan-installer.sh
#
# Authorized use only: SentinelScan may test only systems and networks you
# own or have written permission to test.
set -eu

OWNER="Devraj192"
REPO="sentinel-scanner"
VERSION="${VERSION:-2.0.0}"
PREFIX="${PREFIX:-/usr/local}"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64) TARGET="x86_64-unknown-linux-musl" ;;
    aarch64|arm64) TARGET="aarch64-unknown-linux-musl" ;;
    *) echo "error: unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

need() {
    command -v "$1" >/dev/null 2>&1 || { echo "error: missing required tool: $1" >&2; exit 1; }
}
need curl
need sha256sum
need tar
need mktemp

BASE="https://github.com/$OWNER/$REPO/releases/download/v$VERSION"
ARCHIVE="sentinelscan-v$VERSION-$TARGET.tgz"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

echo "Downloading $ARCHIVE ..."
curl -LsSf --proto '=https' "$BASE/$ARCHIVE" -o "$WORK/$ARCHIVE"
echo "Downloading checksums ..."
curl -LsSf --proto '=https' "$BASE/SHA256SUMS" -o "$WORK/SHA256SUMS"

echo "Verifying checksum ..."
if ! (cd "$WORK" && grep " $ARCHIVE\$" SHA256SUMS | sha256sum -c -); then
    echo "error: checksum verification failed for $ARCHIVE; refusing to install." >&2
    echo "Fix: download the files yourself and compare against the release page." >&2
    exit 1
fi

echo "Installing ..."
tar -xzf "$WORK/$ARCHIVE" -C "$WORK"
install -m 755 "$WORK/sentinelscan" "$PREFIX/bin/sentinelscan" 2>/dev/null || {
    echo "error: cannot write to $PREFIX/bin. Re-run with sudo or set PREFIX=\$HOME/.local." >&2
    exit 1
}

echo "Installed sentinelscan $("$PREFIX/bin/sentinelscan" --version) to $PREFIX/bin/sentinelscan"
echo "Authorized use only: scan only systems and networks you own or have written permission to test."
echo "Next: sentinelscan doctor"
