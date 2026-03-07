#!/usr/bin/env bash
# Build the tahini-sidecar Docker image (x86_64 Linux).
# Extra args are forwarded to docker build, e.g.:
#   bazel run //:docker_build -- --build-arg SGX_MODE=HW --build-arg AZURE=1
set -e
cd "${BUILD_WORKSPACE_DIRECTORY:-.}"
exec docker build "$@" -t tahini-sidecar .
