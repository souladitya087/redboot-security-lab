#!/bin/bash
# ==============================================================================
# RedBoot Hardware & Environment Detection Utility
# Inspects block devices, network interfaces, CPU, and RAM without touching disks.
# ==============================================================================
set -euo pipefail

echo "========================================================"
echo " RedBoot Hardware Discovery & Environmental Audit"
echo "========================================================"

echo "[*] System Architecture:"
uname -a
echo ""

echo "[*] CPU and Memory:"
lscpu | grep -E "Model name|Architecture|CPU\(s\):|Thread|Core" || true
free -h
echo ""

echo "[*] Detected Block Devices (Read-Only Status Check):"
lsblk -o NAME,SIZE,TYPE,FSTYPE,RO,MOUNTPOINT,MODEL
echo ""

echo "[*] Network Interfaces:"
ip -br link
echo ""

echo "[*] IP Address Allocation:"
ip -br addr
echo ""

echo "[*] Write-Blocker Status Check:"
for dev in $(lsblk -d -n -o NAME | grep -v '^loop'); do
    ro_val=$(cat /sys/block/"${dev}"/ro 2>/dev/null || echo "N/A")
    echo "  Device /dev/${dev} -> Read-Only flag: ${ro_val}"
done
echo "========================================================"
