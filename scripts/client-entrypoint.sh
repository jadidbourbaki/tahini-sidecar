#!/usr/bin/env bash
# Client entrypoint: wait for server credentials, then connect with delegated TLS
set -e

SHARED_DIR="/shared"
WORKSPACE="/workspace"
SERVER_ADDR="server:8443"
MAA_ENDPOINT="${MAA_ENDPOINT:-https://sharedeus.eus.attest.azure.net}"

echo "[client-entrypoint] waiting for delegated credential from server..."

# Wait for the server to publish credentials
TIMEOUT=300
ELAPSED=0
while [ ! -f "$SHARED_DIR/.dc-ready" ]; do
    sleep 1
    ELAPSED=$((ELAPSED + 1))
    if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
        echo "[client-entrypoint] ERROR: timed out waiting for credentials"
        exit 1
    fi
done

echo "[client-entrypoint] credentials found, waiting for attestation data..."

# Wait for the sidecar to finish SGX/DCAP attestation and write the JSON.
# In HW mode this can take 30+ seconds (QE init, collateral fetch from Azure).
ELAPSED=0
while [ ! -f "$SHARED_DIR/attestation.json" ]; do
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
        echo "[client-entrypoint] ERROR: timed out waiting for attestation data"
        exit 1
    fi
done

echo "[client-entrypoint] attestation data ready, waiting for server to accept connections..."

# Wait for the rpc-server (exec'd by sidecar after attestation) to bind.
ELAPSED=0
while ! nc -z server 8443 2>/dev/null; do
    sleep 1
    ELAPSED=$((ELAPSED + 1))
    if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
        echo "[client-entrypoint] ERROR: timed out waiting for server on $SERVER_ADDR"
        exit 1
    fi
done

echo "[client-entrypoint] connecting to $SERVER_ADDR with delegated TLS..."

exec /usr/local/bin/rpc-client \
    --attestation "$SHARED_DIR/attestation.json" \
    --dc-sig "$SHARED_DIR/fizz_client.json" \
    --dc-cert "$SHARED_DIR/fizz.crt" \
    --server "$SERVER_ADDR" \
    --maa-endpoint "$MAA_ENDPOINT"
