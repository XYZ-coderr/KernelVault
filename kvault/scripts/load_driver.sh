#!/usr/bin/env bash
# ==============================================================================
# load_driver.sh - Kernel Module Insertion & Device Node Permission Setup (kvault)
# ==============================================================================
set -euo pipefail

MODULE_NAME="kvault"
DEV_NODE="/dev/${MODULE_NAME}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRIVER_DIR="${SCRIPT_DIR}/../driver"
KO_FILE="${DRIVER_DIR}/${MODULE_NAME}.ko"

echo "[INFO] Checking root privileges..."
if [[ $EUID -ne 0 ]]; then
   echo "[ERROR] This script must be run as root (use sudo)." >&2
   exit 1
fi

if lsmod | grep -q "^${MODULE_NAME} "; then
    echo "[WARN] Module ${MODULE_NAME} is already loaded in kernel."
else
    if [[ ! -f "${KO_FILE}" ]]; then
        echo "[INFO] Compiled module ${KO_FILE} not found. Attempting to build driver..."
        make -C "${DRIVER_DIR}"
    fi

    echo "[INFO] Inserting kernel module: ${KO_FILE}..."
    insmod "${KO_FILE}"
    echo "[SUCCESS] insmod executed cleanly."
fi

# Wait for udev to generate device node
RETRIES=10
while [[ ! -c "${DEV_NODE}" && $RETRIES -gt 0 ]]; do
    sleep 0.1
    RETRIES=$((RETRIES - 1))
done

if [[ ! -c "${DEV_NODE}" ]]; then
    echo "[WARN] Device node ${DEV_NODE} not created by devtmpfs. Creating manually via /proc/devices..."
    MAJOR=$(awk "\$2==\"${MODULE_NAME}\" {print \$1}" /proc/devices)
    if [[ -n "${MAJOR}" ]]; then
        mknod "${DEV_NODE}" c "${MAJOR}" 0
    else
        echo "[ERROR] Could not detect major number in /proc/devices." >&2
        exit 1
    fi
fi

# Set accessible permissions for secure file storage workers
chmod 0666 "${DEV_NODE}"
echo "[SUCCESS] Set permissions 0666 on ${DEV_NODE}"
dmesg | tail -n 5 | grep "kvault" || true
echo "[SUCCESS] Kernel accelerator ready for kvault operations."
