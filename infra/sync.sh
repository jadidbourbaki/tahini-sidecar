#!/bin/bash

set -e

# Default values
USER="root"
REMOTE_PATH="/root/tahini-sidecar"

if [ $# -ne 1 ]; then
    echo "Sync to a Linode instance"
    echo "Usage: $0 <ip_address>"
    exit 1
fi

REMOTE="${USER}@$1"

# Get the git root directory
GIT_ROOT="$(git rev-parse --show-toplevel)"

echo "Syncing ${GIT_ROOT} to ${REMOTE}:${REMOTE_PATH}"
echo ""

CMD="mkdir -p ${REMOTE_PATH}"
# shellcheck disable=SC2029
ssh "${REMOTE}" "${CMD}"

# NOTE(jadidbourbaki): rsync commands to remind me
# -a: archive mode (preserves permissions, timestamps, etc.)
# -v: verbose
# -z: compress during transfer
# --delete: delete files on remote that don't exist locally
rsync -avz \
    --delete \
    "${GIT_ROOT}/" "${REMOTE}:${REMOTE_PATH}/"

echo ""
echo "Sync completed successfully!"
echo "Remote location: ${REMOTE}:${REMOTE_PATH}"
