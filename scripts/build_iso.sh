#!/bin/bash
# ==============================================================================
# RedBoot Live ISO Build Automation Script
# Builds Debian 12 Bookworm live ISO using live-build (or inside Docker).
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build/live-iso"
OUTPUT_DIR="$PROJECT_ROOT/output"

echo "=========================================================="
echo " RedBoot Live ISO Image Builder"
echo "=========================================================="

mkdir -p "$OUTPUT_DIR"

if command -v lb >/dev/null 2>&1; then
    echo "[+] Native live-build detected."
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    
    echo "[*] Copying configuration..."
    cp -r "$PROJECT_ROOT/boot/live-build/"* .
    
    echo "[*] Cleaning previous build artifacts..."
    lb clean --all || true
    
    echo "[*] Running lb config..."
    bash auto/config
    
    echo "[*] Injecting RedBoot codebase into chroot..."
    mkdir -p config/includes.chroot/opt/redboot
    rsync -av --exclude '.git' --exclude 'build' --exclude '__pycache__' \
        "$PROJECT_ROOT/" config/includes.chroot/opt/redboot/
        
    echo "[*] Building ISO (requires root privileges)..."
    sudo lb build
    
    if [ -f live-image-amd64.hybrid.iso ]; then
        mv live-image-amd64.hybrid.iso "$OUTPUT_DIR/redboot-live-amd64.iso"
        echo "[+] Successfully built: $OUTPUT_DIR/redboot-live-amd64.iso"
        sha256sum "$OUTPUT_DIR/redboot-live-amd64.iso" | tee "$OUTPUT_DIR/redboot-live-amd64.iso.sha256"
    fi
elif command -v docker >/dev/null 2>&1; then
    echo "[*] Native live-build not found. Using Docker container to build ISO..."
    docker run --privileged --rm \
        -v "$PROJECT_ROOT:/workspace" \
        debian:bookworm \
        bash -c "
            apt-get update && apt-get install -y live-build debootstrap isolinux rsync sudo
            cd /workspace
            mkdir -p /workspace/build/live-iso
            cd /workspace/build/live-iso
            cp -r /workspace/boot/live-build/* .
            bash auto/config
            mkdir -p config/includes.chroot/opt/redboot
            rsync -av --exclude '.git' --exclude 'build' --exclude '__pycache__' /workspace/ config/includes.chroot/opt/redboot/
            lb build
            mv live-image-amd64.hybrid.iso /workspace/output/redboot-live-amd64.iso
            sha256sum /workspace/output/redboot-live-amd64.iso > /workspace/output/redboot-live-amd64.iso.sha256
        "
    echo "[+] Docker build completed."
else
    echo "[!] Error: Neither 'lb' (live-build) nor 'docker' is available on this system."
    echo "    To build the ISO, run this script on a Debian/Ubuntu system with live-build or Docker installed."
    exit 1
fi
