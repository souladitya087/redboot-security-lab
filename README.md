# RedBoot — Bootable Security Assessment & Forensic Analysis Environment

<p align="center">
  <strong>An academic bootable platform for system security assessment, vulnerability analysis, digital forensics, and evidence collection.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/phase-1%20foundation-blue" alt="Phase 1">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/python-3.11%2B-yellow" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/status-in%20development-orange" alt="In Development">
</p>

---

## ⚠️ Authorized Use Only

> **RedBoot is an academic project designed exclusively for use in authorized, isolated laboratory environments.** Unauthorized use against systems you do not own or have explicit written permission to test is **illegal and unethical**. All demonstrations and experiments must be conducted within controlled lab setups.

---

## Overview

RedBoot provides a self-contained, bootable Linux environment that consolidates the core activities of a security assessment engagement:

| Module | Purpose |
|---|---|
| **Reconnaissance** | Network and service discovery within authorized scope |
| **System Assessment** | Configuration auditing, access control evaluation |
| **Vulnerability Assessment** | CVE identification, service version analysis |
| **Anonymity / Non-Traceability** | Academic study of non-traceable assessment techniques |
| **Digital Forensics** | Disk imaging, file carving, timeline analysis |
| **Evidence Collection** | Cryptographic integrity, chain-of-custody logging |
| **Reporting** | Professional HTML/PDF/JSON report generation |
| **Lab Scenarios** | Reproducible, isolated test environments |

## Academic Basis

This project is based on the business case *"System Hacking with Bootable Drives in Cyber Security"* and fulfils final-year academic requirements for demonstrating practical security assessment and forensic analysis capabilities.

---

## Architecture

See the full [Technical Architecture](docs/architecture/ARCHITECTURE.md) document for detailed module responsibilities, data flow diagrams, and design decisions.

### High-Level Structure

```
redboot-security-lab/
├── docs/                 # Documentation & academic deliverables
├── boot/                 # Bootable environment (Debian live-build)
├── modules/              # Core assessment & forensic modules
│   ├── core/             # Shared utilities (config, logging, scope)
│   ├── reconnaissance/   # Network reconnaissance
│   ├── system-assessment/ # System security assessment
│   ├── vulnerability-assessment/ # Vulnerability scanning
│   ├── anonymity/        # Non-traceability layer
│   ├── forensics/        # Digital forensics
│   └── evidence/         # Evidence collection & integrity
├── reporting/            # Report generation engine
├── lab/                  # Docker-based lab environments
├── scripts/              # Utility scripts
└── tests/                # Unit and integration tests
```

---

## Getting Started

### Prerequisites

- Python 3.11+
- Docker & Docker Compose (for lab environments)
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/<your-org>/redboot-security-lab.git
cd redboot-security-lab

# Install core dependencies
pip install -r requirements.txt

# Verify installation
python -m pytest tests/ -v
```

### Running Lab Scenarios

```bash
# Start the isolated lab environment
cd lab/docker
docker-compose up -d

# Run a scenario
python scripts/run_scenario.py --scenario lab/scenarios/basic_recon.yaml
```

---

## Development Phases

| Phase | Description | Status |
|---|---|---|
| 1 | Architecture & repository foundation | 🟢 In Progress |
| 2 | Bootable environment | ⬜ Planned |
| 3 | Assessment engine (recon, vuln, system) | ⬜ Planned |
| 4 | Forensic capabilities | ⬜ Planned |
| 5 | Reporting engine | ⬜ Planned |
| 6 | Controlled lab & experiments | ⬜ Planned |
| 7 | Final-year documentation & evaluation | ⬜ Planned |

---

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to this project.

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

- Academic business case: *"System Hacking with Bootable Drives in Cyber Security"*
- Built for final-year academic evaluation
- All tools and techniques are used exclusively in authorized, controlled environments
