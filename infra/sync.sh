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

# Use workspace root when run via 'bazel run'; else git root (so we sync the real repo, not the execroot)
if [ -n "${BUILD_WORKSPACE_DIRECTORY:-}" ] && [ -f "${BUILD_WORKSPACE_DIRECTORY}/MODULE.bazel" ]; then
    GIT_ROOT="$BUILD_WORKSPACE_DIRECTORY"
else
    GIT_ROOT="$(git rev-parse --show-toplevel)"
fi
[ ! -f "${GIT_ROOT}/MODULE.bazel" ] && {
    echo "error: MODULE.bazel not found in ${GIT_ROOT}" >&2
    exit 1
}

echo "Syncing ${GIT_ROOT} to ${REMOTE}:${REMOTE_PATH}"
echo ""

CMD="mkdir -p ${REMOTE_PATH}"
# shellcheck disable=SC2029
ssh "${REMOTE}" "${CMD}"

# -a: archive; -v: verbose; -z: compress; --delete: remove remote files not present locally
rsync -avz \
    --delete \
    "${GIT_ROOT}/" "${REMOTE}:${REMOTE_PATH}/"

# Fix ownership on remote so root can read all files (remote rsync may not support --chown)
# shellcheck disable=SC2029
ssh "${REMOTE}" "chown -R root:root ${REMOTE_PATH}"

# Verify MODULE.bazel exists on the remote (so 'bazel run' works)
# shellcheck disable=SC2029
if ! ssh "${REMOTE}" "test -f ${REMOTE_PATH}/MODULE.bazel"; then
    echo "warning: MODULE.bazel not found on remote at ${REMOTE_PATH}. Run 'bazel run //:sync' from the repo root so the full tree (including MODULE.bazel) is synced." >&2
    exit 1
fi

echo ""
echo "Sync completed successfully!"
echo "Remote location: ${REMOTE}:${REMOTE_PATH}"
