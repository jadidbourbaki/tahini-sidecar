#!/usr/bin/env bash
# Server entrypoint: generate delegated credential, then run sidecar → RPC server
set -e

SHARED_DIR="/shared"
WORKSPACE="/workspace"

echo "[server-entrypoint] starting server setup..."

# Source SGX SDK environment
source "$SGX_SDK/environment"

cd "$WORKSPACE"

# Step 1: generate TLS certificate with DC extension (if not already present)
if [ ! -f fizz.crt ] || [ ! -f fizz.key ]; then
    echo "[server-entrypoint] generating TLS certificate with DC extension..."
    bash third_party/fizz-rs/generate_certificate.sh
fi

# Step 2: run fizz-sidecar to generate delegated credential
# The C++ binary writes to /tmp/fizz_server.json and /tmp/fizz_client.json
echo "[server-entrypoint] generating delegated credential..."
/usr/local/bin/fizz-sidecar

# Step 3: copy artifacts to shared volume
echo "[server-entrypoint] publishing credential artifacts to $SHARED_DIR..."
cp /tmp/fizz_server.json "$SHARED_DIR/fizz_server.json"
cp /tmp/fizz_client.json "$SHARED_DIR/fizz_client.json"
cp fizz.crt "$SHARED_DIR/fizz.crt"

# Step 4: signal that credentials are ready
touch "$SHARED_DIR/.dc-ready"

# Step 5: build service argv and exec the sidecar
# The sidecar will hash the RPC server binary, do SGX attestation,
# then execveat the RPC server with --tahini-secret + DC args
echo "[server-entrypoint] launching tahini sidecar..."

# Mark server as ready once the sidecar has written attestation.json.
# DCAP attestation in HW mode can take 30+ seconds (QE init + collateral fetch).
(
    while [ ! -f "$SHARED_DIR/attestation.json" ]; do sleep 2; done
    touch "$SHARED_DIR/.server-ready"
) &

exec /usr/local/bin/sidecar \
    --tahini-dc "$SHARED_DIR/fizz_server.json" \
    --tahini-dc-cert "$SHARED_DIR/fizz.crt" \
    --tahini-dc-sig "$SHARED_DIR/fizz_client.json" \
    --tahini-quote-out "$SHARED_DIR/attestation.json" \
    /usr/local/bin/rpc-server \
    --port 8443
