#!/usr/bin/env bash
# Run the tahini-sidecar container with workspace mounted at /workspace (x86_64 Linux).
# In HW mode, passes through SGX devices and AESM socket for real attestation.
set -e
WORKSPACE="${BUILD_WORKSPACE_DIRECTORY:-$(pwd)}"

SGX_FLAGS=""
if [ -c /dev/sgx_enclave ] || [ -c /dev/sgx/enclave ]; then
    [ -c /dev/sgx_enclave ]   && SGX_FLAGS="$SGX_FLAGS --device /dev/sgx_enclave"
    [ -c /dev/sgx_provision ] && SGX_FLAGS="$SGX_FLAGS --device /dev/sgx_provision"
    [ -c /dev/sgx/enclave ]   && SGX_FLAGS="$SGX_FLAGS --device /dev/sgx/enclave"
    [ -c /dev/sgx/provision ] && SGX_FLAGS="$SGX_FLAGS --device /dev/sgx/provision"
    [ -S /var/run/aesmd/aesm.socket ] && SGX_FLAGS="$SGX_FLAGS -v /var/run/aesmd:/var/run/aesmd"
fi

exec docker run -it --rm -v "$WORKSPACE:/workspace" $SGX_FLAGS tahini-sidecar "$@"
