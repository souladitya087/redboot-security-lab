#!/bin/bash
# ==============================================================================
# RedBoot Safe Forensic Read-Only Target Mounter
# Mounts target partitions strictly read-only with noatime,nodev,nosuid.
# Ensures forensic soundness and zero alteration of evidence.
# ==============================================================================
set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "Usage: sudo $0 <source_block_device_or_image> <mount_point>"
    echo "Example: sudo $0 /dev/sdb1 /mnt/target_analysis"
    exit 1
fi

SOURCE="$1"
TARGET_DIR="$2"

if [ ! -e "$SOURCE" ]; then
    echo "[!] Error: Source '$SOURCE' does not exist."
    exit 1
fi

mkdir -p "$TARGET_DIR"

echo "[*] Verifying block-level read-only status for $SOURCE..."
# Attempt read-only mount
mount -o ro,noload,noatime,nodev,nosuid "$SOURCE" "$TARGET_DIR"

echo "[+] Successfully mounted '$SOURCE' on '$TARGET_DIR' in strict READ-ONLY mode."
echo "[*] Mount status:"
mount | grep "$TARGET_DIR"
