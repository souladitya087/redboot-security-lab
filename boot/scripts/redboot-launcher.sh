#!/bin/bash
# ==============================================================================
# RedBoot Live System Auto-Launcher
# Starts up environment upon tty1 login
# ==============================================================================
set -e

# Apply hardening and read-only protections
if [ -f /etc/sysctl.d/99-redboot-security.conf ]; then
    sysctl --system >/dev/null 2>&1 || true
fi

# Set PYTHONPATH to project root
export PYTHONPATH="/opt/redboot:${PYTHONPATH:-}"

echo "[*] Initializing RedBoot Academic Security Lab..."
bash "$(dirname "${BASH_SOURCE[0]}")/detect-hardware.sh"
echo ""
echo "[*] Launching RedBoot Menu..."
exec bash "$(dirname "${BASH_SOURCE[0]}")/redboot-menu.sh"
