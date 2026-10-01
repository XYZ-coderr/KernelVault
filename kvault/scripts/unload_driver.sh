#!/usr/bin/env bash
# ==============================================================================
# unload_driver.sh - Graceful Kernel Module Removal & Device Node Teardown (kvault)
# ==============================================================================
set -euo pipefail

MODULE_NAME="kvault"
DEV_NODE="/dev/${MODULE_NAME}"

echo "[INFO] Checking root privileges..."
if [[ $EUID -ne 0 ]]; then
   echo "[ERROR] This script must be run as root (use sudo)." >&2
   exit 1
fi

if ! lsmod | grep -q "^${MODULE_NAME} "; then
    echo "[INFO] Module ${MODULE_NAME} is not loaded. Nothing to unload."
    exit 0
fi

echo "[INFO] Removing kernel module: ${MODULE_NAME}..."
rmmod "${MODULE_NAME}"
echo "[SUCCESS] rmmod completed cleanly."

if [[ -e "${DEV_NODE}" ]]; then
    rm -f "${DEV_NODE}"
    echo "[INFO] Removed lingering device node ${DEV_NODE}"
fi

dmesg | tail -n 5 | grep "kvault" || true
echo "[SUCCESS] Kernel driver unloaded and keying memory purged."
