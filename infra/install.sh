#!/usr/bin/env bash
# Install Bazelisk on this host (Bazel version launcher; uses .bazelversion in the repo).
# Run from the repo root after sync, or from anywhere with the repo available.
# Usage: ./infra/install.sh   (or from repo root: infra/install.sh)
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

ARCH="$(uname -m)"
if [ "$ARCH" != "x86_64" ]; then
    echo "error: this script installs the linux-amd64 Bazelisk binary (this host is $ARCH)" >&2
    exit 1
fi

URL="https://github.com/bazelbuild/bazelisk/releases/latest/download/bazelisk-linux-amd64"
DEST="${INSTALL_DIR:-/usr/local/bin}/bazel"

echo "Installing Bazelisk from ${URL} -> ${DEST}"

if [ -w "$(dirname "$DEST")" ]; then
    wget -qO "$DEST" "$URL"
    chmod +x "$DEST"
else
    sudo wget -qO "$DEST" "$URL"
    sudo chmod +x "$DEST"
fi

"$DEST" version
echo "Done. Bazelisk is at $DEST (run Bazel from the repo root so it finds MODULE.bazel)"
