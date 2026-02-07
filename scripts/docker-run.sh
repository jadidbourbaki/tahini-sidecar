#!/usr/bin/env bash
# Run the tahini-sidecar container with workspace mounted at /workspace (x86_64 Linux).
set -e
WORKSPACE="${BUILD_WORKSPACE_DIRECTORY:-$(pwd)}"
exec docker run -it --rm -v "$WORKSPACE:/workspace" tahini-sidecar "$@"
