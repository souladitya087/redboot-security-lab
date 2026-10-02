# RedBoot — Bootable Security Assessment & Forensic Analysis Environment

<p align="center">
  <strong>An academic bootable platform for system security assessment, vulnerability analysis, digital forensics, and cryptographic evidence collection.</strong>
</p>

<p align="center">
  <a href="https://github.com/souladitya087/redboot-security-lab/actions/workflows/ci.yml">
    <img src="https://github.com/souladitya087/redboot-security-lab/actions/workflows/ci.yml/badge.svg" alt="CI Status">
  </a>
  <img src="https://img.shields.io/badge/progress-100%25%20completed-brightgreen" alt="Progress">
  <img src="https://img.shields.io/badge/tests-62%20passed-success" alt="Tests">
  <img src="https://img.shields.io/badge/version-1.0.0-blue" alt="Version 1.0.0">
  <img src="https://img.shields.io/badge/python-3.11%2B-yellow" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/status-production%20ready-brightgreen" alt="Status">
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
| **Lab Scenarios & Docker** | Isolated Docker bridge (`192.168.56.0/24`), 4 target containers, 5 scripted scenarios | 🟢 Complete |
| **Academic Deliverables** | Research thesis monograph, empirical evaluation data, operator handbook | 🟢 Complete |

---

## Academic Basis

This project is developed under the business case *"System Hacking with Bootable Drives in Cyber Security"* and fulfills final-year academic requirements for demonstrating practical security assessment, live-boot penetration testing techniques, forensic integrity preservation, and chain-of-custody tracking in controlled laboratory environments.

- **Academic Monograph:** [docs/academic/ACADEMIC_REPORT.md](docs/academic/ACADEMIC_REPORT.md)
- **Empirical Evaluation Data:** [docs/academic/EVALUATION_RESULTS.md](docs/academic/EVALUATION_RESULTS.md)
- **Operator Handbook & Lab Manual:** [docs/user-guide/USER_GUIDE.md](docs/user-guide/USER_GUIDE.md)

---

## Architecture & Repository Structure

See the complete [Technical Architecture](docs/architecture/ARCHITECTURE.md) document for data flow diagrams, module interfaces, and security controls.

```
redboot-security-lab/
├── docs/                      # Documentation & academic deliverables
│   ├── academic/              # Academic thesis and empirical benchmark results
│   │   ├── ACADEMIC_REPORT.md    # Full academic dissertation
│   │   └── EVALUATION_RESULTS.md # Latency, CVSS accuracy, carving, & ledger metrics
│   ├── architecture/          # Technical Architecture documentation
│   ├── user-guide/            # Operator handbook (USER_GUIDE.md)
│   └── PROJECT_STATUS.md      # Detailed progress and milestone tracking (100% complete)
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
│   ├── docker/                # Multi-container isolated lab (web, db, ftp-ssh, forensics)
│   └── scenarios/             # Scripted benchmark scenarios (YAML)
├── scripts/                   # ISO build automation (`build_iso.sh`) and scenario runner
├── redboot.py                 # Top-level unified CLI for all modules and scenarios
└── tests/                     # Test suite (62 unit and integration tests passing)
```

---

## Getting Started

### Prerequisites

- **Python:** 3.11+ (Python 3.11, 3.12, 3.14 tested)
- **Dependencies:** `pip install -r requirements.txt` (and `requirements-dev.txt` for development)
- **Optional (for live ISO generation):** Debian/Ubuntu with `live-build` or Docker installed
- **Optional (for isolated lab):** Docker and Docker Compose

### Installation & Test Verification

```bash
# Clone the repository
git clone https://github.com/souladitya087/redboot-security-lab.git
cd redboot-security-lab

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run complete test suite (62 tests)
pytest

# Verify code formatting and linting
flake8 modules/ reporting/ scripts/ tests/ redboot.py --max-line-length=120
black --check modules/ reporting/ scripts/ tests/ redboot.py
```

---

## Unified RedBoot CLI (`redboot.py`)

RedBoot provides a top-level command-line tool connecting all platform engines:

```bash
# Check platform component health & readiness
python redboot.py status

# Run scope-enforced network reconnaissance
python redboot.py recon scan -t 192.168.56.0/24 -p 21,22,80,443,3306,6379,8080 -o output/recon.json

# Audit offline mounted target filesystem
python redboot.py audit full --target /mnt/target -o output/audit.json

# Scan findings for CVE vulnerabilities & CVSS scores
python redboot.py vuln scan -i output/recon.json -o output/vulns.json

# Ingest forensic artifact into tamper-evident vault
python redboot.py evidence collect -f output/target.raw -d "Raw image" -c "operator"

# Verify cryptographic ledger and vault integrity
python redboot.py evidence verify --vault-dir output/evidence_vault/

# Execute an automated scenario
python redboot.py scenario -s lab/scenarios/basic_recon.yaml -o output/scn01/

# Generate client-ready reports (HTML, Markdown, JSON)
python redboot.py report generate -d output/scn01/ --case-id CASE-2026-001
```

---

## Controlled Multi-Container Lab

RedBoot includes a complete isolated Docker simulation environment (`192.168.56.0/24`):

```bash
# Start all 4 target containers
cd lab/docker/
docker compose up -d

# Targets active:
# - 192.168.56.10: Web (Apache 2.4.49 - CVE-2021-41773)
# - 192.168.56.20: DB (MySQL 5.7 & Redis 6.0 - CVE-2022-0543)
# - 192.168.56.30: Services (vsftpd 2.3.4 - CVE-2011-2523, OpenSSH 7.4p1, Telnet)
# - 192.168.56.40: Forensics target (disk.raw seeded with deleted files)

# Stop the lab
docker compose down
```

---

## Automated Scenarios

Execute reproducible scenarios defined in `lab/scenarios/`:
```bash
# 1. Basic Reconnaissance
python redboot.py scenario -s lab/scenarios/basic_recon.yaml

# 2. System Security Audit
python redboot.py scenario -s lab/scenarios/system_audit.yaml

# 3. Vulnerability Assessment
python redboot.py scenario -s lab/scenarios/vuln_scan.yaml

# 4. Forensic Investigation
python redboot.py scenario -s lab/scenarios/forensic_investigation.yaml

# 5. Full End-to-End Engagement
python redboot.py scenario -s lab/scenarios/full_engagement.yaml
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
| **Phase 6** | Controlled lab & reproducible scenario runner | 🟢 Complete | 100% |
| **Phase 7** | Final-year academic documentation & evaluation | 🟢 Complete | 100% |

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
