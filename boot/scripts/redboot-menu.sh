#!/bin/bash
# ==============================================================================
# RedBoot Interactive Console Menu
# TUI dashboard for launching assessment, forensics, and scenario runs.
# ==============================================================================
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

show_menu() {
    clear
    cat << "EOF"
================================================================================
  ____           _ ____              _     
 |  _ \ ___   __| | __ )  ___   ___ | |_   RedBoot Security Assessment &
 | |_) / _ \ / _` |  _ \ / _ \ / _ \| __|  Digital Forensics Console
 |  _ <  __/| (_| | |_) | (_) | (_) | |_   Version 1.0 (Live Environment)
 |_| \_\___| \__,_|____/ \___/ \___/ \__|  Academic Security Evaluation
================================================================================
  [1] Hardware & Storage Discovery (Read-Only Audit)
  [2] Run Network Reconnaissance Scan
  [3] Run System Security Assessment
  [4] Run Vulnerability Assessment Scanner
  [5] Anonymity & Anti-Forensics Verification
  [6] Forensic Disk Acquisition (Bit-for-Bit Imaging)
  [7] Digital Evidence Collection & Hash Verification
  [8] Run Automated Lab Scenario (Docker / Host-only)
  [9] Generate Assessment & Forensic Report
  [0] Open Bash Terminal Shell
  [Q] Exit / Power off
================================================================================
EOF
}

while true; do
    show_menu
    read -rp "Select an option [0-9, Q]: " choice
    case "$choice" in
        1)
            bash "$PROJECT_ROOT/boot/scripts/detect-hardware.sh"
            read -rp "Press Enter to return to menu..."
            ;;
        2)
            python3 -m modules.reconnaissance.cli --help || true
            read -rp "Press Enter to return to menu..."
            ;;
        3)
            python3 -m modules.system_assessment.cli --help || true
            read -rp "Press Enter to return to menu..."
            ;;
        4)
            python3 -m modules.vulnerability_assessment.cli --help || true
            read -rp "Press Enter to return to menu..."
            ;;
        5)
            python3 -m modules.anonymity.cli --help || true
            read -rp "Press Enter to return to menu..."
            ;;
        6)
            python3 -m modules.forensics.cli --help || true
            read -rp "Press Enter to return to menu..."
            ;;
        7)
            python3 -m modules.evidence.cli --help || true
            read -rp "Press Enter to return to menu..."
            ;;
        8)
            python3 "$PROJECT_ROOT/scripts/run_scenario.py" --help || true
            read -rp "Press Enter to return to menu..."
            ;;
        9)
            python3 -m reporting.cli --help || true
            read -rp "Press Enter to return to menu..."
            ;;
        0)
            echo "Entering interactive shell. Type 'exit' to return to menu."
            /bin/bash
            ;;
        [qQ])
            echo "Exiting RedBoot Console."
            break
            ;;
        *)
            echo "Invalid selection. Please choose an option from the menu."
            sleep 1
            ;;
    esac
done
