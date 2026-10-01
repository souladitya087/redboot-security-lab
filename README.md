# RedBoot — Bootable Security Assessment & Forensic Analysis Environment

<p align="center">
  <strong>An academic bootable platform for system security assessment, vulnerability analysis, digital forensics, and cryptographic evidence collection.</strong>
</p>

<p align="center">
  <a href="https://github.com/souladitya087/redboot-security-lab/actions/workflows/ci.yml">
    <img src="https://github.com/souladitya087/redboot-security-lab/actions/workflows/ci.yml/badge.svg" alt="CI Status">
  </a>
  <img src="https://img.shields.io/badge/progress-72%25%20completed-brightgreen" alt="Progress">
  <img src="https://img.shields.io/badge/tests-57%20passed-success" alt="Tests">
  <img src="https://img.shields.io/badge/python-3.11%2B-yellow" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/status-active%20development-blue" alt="Status">
</p>

---

## ⚠️ Authorized Use Only

> **RedBoot is an academic project designed exclusively for use in authorized, isolated laboratory environments.** Unauthorized use against systems you do not own or have explicit written permission to test is **illegal and unethical**. All demonstrations and experiments must be conducted within controlled lab setups.

---

## Overview

RedBoot provides a self-contained, bootable Linux environment (Debian 12 Bookworm live) that consolidates the entire lifecycle of a security assessment and forensic engagement into an integrated framework:

| Module | Purpose | Status |
|---|---|---|
| **Core Framework** | Scope enforcement, configuration management, structured logging | 🟢 Complete |
| **Boot System** | Debian 12 Bookworm live-build, write-blocking mounter, GRUB menu | 🟢 Complete |
| **Reconnaissance** | Scope-enforced network scanner, service banner grabbing, DNS enum, OS fingerprinting | 🟢 Complete |
| **System Assessment** | Offline/live filesystem audit, UID 0 analysis, SUID/GTFOBins detection, CIS compliance | 🟢 Complete |
| **Vulnerability Assessment** | Curated CVE database, regex banner matching, cleartext protocol detection, CVSS scoring | 🟢 Complete |
| **Anonymity / Non-Traceability** | Tor SOCKS5 proxy manager, MAC address randomizer, DNS leak firewall rules, anti-forensics | 🟢 Complete |
| **Digital Forensics** | Bit-for-bit raw disk imager, magic-byte file carver, MACB timeline generator, log correlation | 🟢 Complete |
| **Evidence Collection** | Append-only cryptographic Chain-of-Custody ledger, SHA-256/512 vaulting, integrity verifier | 🟢 Complete |
| **Reporting Engine** | Unified multi-format reporting (interactive HTML dashboard, Markdown, JSON) | 🟢 Complete |
| **Lab Scenarios** | Docker-compose vulnerable target containers and scripted benchmark scenarios | ⬜ Planned |
| **Academic Deliverables** | Final-year academic thesis report, evaluation data, and operator handbook | ⬜ Planned |

---

## Academic Basis

This project is developed under the business case *"System Hacking with Bootable Drives in Cyber Security"* and fulfills final-year academic requirements for demonstrating practical security assessment, live-boot penetration testing techniques, forensic integrity preservation, and chain-of-custody tracking in controlled laboratory environments.

---

## Architecture & Repository Structure

See the complete [Technical Architecture](docs/architecture/ARCHITECTURE.md) document for data flow diagrams, module interfaces, and security controls.

```
redboot-security-lab/
├── docs/                      # Documentation & academic deliverables
│   ├── architecture/          # Technical Architecture documentation
│   ├── user-guide/            # Operator handbook
│   ├── academic/              # Academic dissertation and evaluation data
│   └── PROJECT_STATUS.md      # Detailed progress and milestone tracking
├── boot/                      # Live bootable environment
│   ├── live-build/            # Debian 12 Bookworm live-build scripts and hooks
│   ├── config/                # Boot configuration (sysctl hardening, read-only policies)
│   └── scripts/               # Write-block mounter, hardware audit, console dashboard
├── modules/                   # Core assessment & forensic engines
│   ├── core/                  # Configuration loader, structured logger, scope validator
│   ├── reconnaissance/        # Scope-enforced network scanner, DNS, OS fingerprinting
│   ├── system_assessment/     # System auditor, SUID/GTFOBins, CIS compliance scoring
│   ├── vulnerability_assessment/ # CVE knowledge base, banner matching, CVSS scoring
│   ├── anonymity/             # Tor/SOCKS5 proxy, MAC spoofer, DNS leak rules, anti-forensics
│   ├── forensics/             # Raw disk imager, file carver, MACB timeline, log analyzer
│   └── evidence/              # Chain-of-Custody ledger, evidence vault, integrity verifier
├── reporting/                 # Unified reporting engine (HTML dashboard, Markdown, JSON)
├── lab/                       # Docker isolated lab environments & scenario definitions
├── scripts/                   # ISO build automation (`build_iso.sh`) and scenario runners
└── tests/                     # Test suite (57 unit tests passing across all modules)
```

---

## Getting Started

### Prerequisites

- **Python:** 3.11+ (Python 3.11, 3.12, 3.14 tested)
- **Dependencies:** `pip install -r requirements.txt` (and `requirements-dev.txt` for development)
- **Optional (for live ISO generation):** Debian/Ubuntu with `live-build` or Docker installed

### Installation & Test Verification

```bash
# Clone the repository
git clone https://github.com/souladitya087/redboot-security-lab.git
cd redboot-security-lab

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run the complete test suite (57 unit tests)
python -m pytest tests/ -v

# Check code formatting and linting
flake8 modules/ reporting/ scripts/ tests/ --max-line-length=120 --statistics
black --check modules/ reporting/ scripts/ tests/
```

---

## Module CLI Reference & Usage Examples

### 1. Scope-Enforced Reconnaissance
Scans targets while strictly enforcing safety boundaries:
```bash
# Scan a single host
python -m modules.reconnaissance.cli --target 192.168.56.10 --ports 21,22,80,443 -o output/recon.json

# Scan an authorized subnet range
python -m modules.reconnaissance.cli --target 192.168.56.0/24 -o output/recon_range.json
```

### 2. System Security & Compliance Audit
Evaluates system configurations, duplicate UID 0 root accounts, sensitive file permissions (`/etc/shadow`), and GTFOBins SUID binaries:
```bash
# Audit live system or an offline mounted target drive
python -m modules.system_assessment.cli --root-dir / --compliance -o output/system_audit.json

# Audit an offline forensic image mounted at /mnt/target
python -m modules.system_assessment.cli --root-dir /mnt/target --compliance
```

### 3. Vulnerability Assessment
Matches discovered services and banners against the CVE database and computes CVSS scores:
```bash
python -m modules.vulnerability_assessment.cli --input-recon output/recon.json -o output/vuln.json
```

### 4. Anonymity & Anti-Forensics Verification
Audits volatile RAM-only execution posture, generates MAC address spoofing plans, and creates DNS leak prevention firewall rules:
```bash
python -m modules.anonymity.cli --check-all --randomize-mac eth0 -o output/anonymity.json
```

### 5. Digital Forensics (Acquisition, Carving, Timeline & Logs)
```bash
# Bit-for-bit raw disk acquisition with simultaneous SHA-256/MD5 hashing
python -m modules.forensics.cli acquire --source /dev/sdb --output output/target_disk.dd --case CASE-001

# File carving by file signatures (PNG, JPG, PDF, ZIP, ELF, SQLite)
python -m modules.forensics.cli carve --image output/target_disk.dd --output-dir output/carved/

# Generate MACB chronological filesystem timeline
python -m modules.forensics.cli timeline --target-dir /mnt/target --csv-output output/timeline.csv

# Forensic log correlation (brute-force attacks, unauthorized sudo access)
python -m modules.forensics.cli analyze-logs --log-file /var/log/auth.log
```

### 6. Evidence Collection & Cryptographic Chain of Custody
```bash
# Collect artifact into evidence vault and record in append-only custody ledger
python -m modules.evidence.cli collect --file output/target_disk.dd --desc "Target disk image" --custodian "Analyst-1"

# Verify custody ledger integrity and validate all file hashes against tampering
python -m modules.evidence.cli verify --vault evidence_vault

# List all archived evidence items
python -m modules.evidence.cli list --vault evidence_vault
```

### 7. Multi-Format Report Generation
Generates executive dashboards, Markdown deliverables, and JSON models from module findings:
```bash
# Generate HTML dashboard, Markdown, and JSON deliverables
python -m reporting.cli --input-dir output/ --format all --case CASE-2026-001
```

### 8. Interactive Boot Menu & Live ISO Generation
```bash
# Launch interactive console menu (included in live boot image)
bash boot/scripts/redboot-menu.sh

# Build Debian 12 Bookworm live ISO (requires live-build or Docker)
bash scripts/build_iso.sh
```

---

## Development Phases

| Phase | Description | Status | Progress |
|---|---|---|---|
| **Phase 1** | Architecture & repository foundation | 🟢 Complete | 100% |
| **Phase 2** | Bootable environment (Debian 12 live-build, write-block, ISO builder) | 🟢 Complete | 100% |
| **Phase 3** | Assessment engine (recon, system, vuln, anonymity) | 🟢 Complete | 100% |
| **Phase 4** | Forensic capabilities & tamper-evident evidence collection | 🟢 Complete | 100% |
| **Phase 5** | Multi-format reporting engine (HTML, Markdown, JSON) | 🟢 Complete | 100% |
| **Phase 6** | Controlled lab & reproducible scenario runner | ⬜ Planned | 0% |
| **Phase 7** | Final-year academic documentation & evaluation | ⬜ Planned | 0% |

> Detailed milestone breakdowns and test metrics are tracked in [docs/PROJECT_STATUS.md](docs/PROJECT_STATUS.md).

---

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on code style, linting, and testing before submitting pull requests.

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

- Academic business case: *"System Hacking with Bootable Drives in Cyber Security"*
- Built for final-year academic evaluation
- All tools and techniques are used exclusively in authorized, controlled laboratory environments
