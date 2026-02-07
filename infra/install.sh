#!/usr/bin/env bash
# Install the Bazel binary (version from .bazelversion) on this host.
# Run from the repo root after sync, or from anywhere with the repo available.
# Usage: ./infra/install.sh   (or from repo root: infra/install.sh)
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BAZELVERSION_FILE="$REPO_ROOT/.bazelversion"

if [ -f "$BAZELVERSION_FILE" ]; then
    BAZEL_VERSION="$(cat "$BAZELVERSION_FILE" | tr -d '\r\n' | xargs)"
else
    BAZEL_VERSION="${BAZEL_VERSION:-8.5.1}"
fi

ARCH="$(uname -m)"
if [ "$ARCH" != "x86_64" ]; then
    echo "error: this script installs the linux-x86_64 Bazel binary (this host is $ARCH)" >&2
    exit 1
fi

URL="https://github.com/bazelbuild/bazel/releases/download/${BAZEL_VERSION}/bazel-${BAZEL_VERSION}-linux-x86_64"
DEST="${INSTALL_DIR:-/usr/local/bin}/bazel"

echo "Installing Bazel ${BAZEL_VERSION} from ${URL} -> ${DEST}"

if [ -w "$(dirname "$DEST")" ]; then
    wget -qO "$DEST" "$URL"
    chmod +x "$DEST"
else
    sudo wget -qO "$DEST" "$URL"
    sudo chmod +x "$DEST"
fi

"$DEST" version
echo "Done. Bazel is at $DEST"
