#!/usr/bin/env bash
# End-to-end demo: builds and runs the server (SGX + delegated TLS) and client
# containers on an SGX-capable host (e.g. Azure DCsv3).
#
# Usage:  bazel run //:demo
set -e
cd "${BUILD_WORKSPACE_DIRECTORY:-.}"

if [ ! -c /dev/sgx_enclave ] && [ ! -c /dev/sgx/enclave ]; then
    echo "error: SGX device not found — this must run on an SGX-capable host"
    echo "       (e.g. Azure Standard_DC1s_v3)"
    exit 1
fi

exec docker compose \
    -f docker-compose.yml \
    -f docker-compose.sgx.yml \
    up --build
