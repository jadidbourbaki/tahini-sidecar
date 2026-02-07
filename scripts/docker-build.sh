#!/usr/bin/env bash
# Build the tahini-sidecar Docker image (x86_64 Linux).
set -e
cd "${BUILD_WORKSPACE_DIRECTORY:-.}"
exec docker build -t tahini-sidecar .
