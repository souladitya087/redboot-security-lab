# Changelog

All notable changes to the RedBoot project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-10-02

### Added
- **Top-Level CLI (`redboot.py`):** Unified entrypoint connecting all assessment, forensics, evidence, and reporting modules.
- **Scenario Runner (`scripts/run_scenario.py`):** Automated stage runner with scope enforcement, evidence auto-vaulting, and multi-format report generation.
- **Controlled Multi-Container Lab (`lab/docker/`):**
  - Isolated Docker network bridge on `192.168.56.0/24`.
  - Web target container simulating Apache 2.4.49 (CVE-2021-41773 & CVE-2021-42013).
  - Database target container simulating MySQL 5.7 and Redis 6.0 (CVE-2022-0543).
  - FTP/SSH target container simulating vsftpd 2.3.4 (CVE-2011-2523), OpenSSH 7.4p1, and Telnet.
  - Forensics target container seeding raw disk images (`target_disk.raw`) with deleted files and anomalous `auth.log` data.
- **Automated Scenario Definitions (`lab/scenarios/`):**
  - `basic_recon.yaml`: Subnet discovery and service fingerprinting.
  - `system_audit.yaml`: Offline filesystem and CIS compliance auditing.
  - `vuln_scan.yaml`: Full vulnerability scan with CVSS v3.1 scoring.
  - `forensic_investigation.yaml`: Raw disk carving, MACB timeline generation, and log analysis.
  - `full_engagement.yaml`: Consolidated multi-stage assessment engagement.
- **Academic Research Monograph (`docs/academic/ACADEMIC_REPORT.md`):** Complete research thesis covering physical bootable attack surfaces, STRIDE threat models, defense-in-depth countermeasures, and ethical frameworks.
- **Empirical Evaluation Data (`docs/academic/EVALUATION_RESULTS.md`):** Benchmark latency tables, CVSS scoring accuracy, 0-byte disk write-blocking proofs, carving recovery metrics, and cryptographic ledger tamper stress testing.
- **Operator Handbook (`docs/user-guide/USER_GUIDE.md`):** Comprehensive operator guide covering USB flashing, live boot modes, console dashboard, CLI commands, and Docker lab setup.
- **Integration Test Suite (`tests/integration/test_scenario_pipeline.py`):** End-to-end tests validating dry-run, full execution, scope enforcement aborts, and CLI commands.

---

## [0.5.0] — 2026-10-01

### Added
- **Reporting Engine (`reporting/`):**
  - Unified multi-format `ReportEngine` aggregating data across all modules.
  - Interactive responsive HTML dashboard (`reporting/templates/report.html`) with dark theme.
  - Markdown formatter (`reporting/formatters/markdown_formatter.py`) for GitHub-flavored reports.
  - JSON formatter (`reporting/formatters/json_formatter.py`) for programmatic consumption.
  - CLI reporting tool (`reporting/cli.py`).
- **Forensic Capabilities & Evidence Collection (`modules/forensics/`, `modules/evidence/`):**
  - Bit-stream raw disk imager (`modules/forensics/imager.py`) with continuous hashing.
  - Magic-byte file carving engine (`modules/forensics/carver.py`) for PNG, JPG, PDF, ZIP, ELF, SQLite.
  - MACB timeline generator (`modules/forensics/timeline.py`) with CSV export.
  - Authentication log correlation analyzer (`modules/forensics/log_analyzer.py`).
  - Cryptographically-chained append-only custody ledger (`modules/evidence/chain_of_custody.py`).
  - Evidence vault collector (`modules/evidence/collector.py`) with dual SHA-256 / SHA-512 hashing.
  - Tamper verifier (`modules/evidence/verifier.py`).
- **Assessment Engine (`modules/`):**
  - Network scanner (`modules/reconnaissance/scanner.py`), DNS enumeration, OS fingerprinting.
  - System filesystem auditor (`modules/system_assessment/auditor.py`) and CIS compliance scoring.
  - CVE database and vulnerability scanner (`modules/vulnerability_assessment/vuln_scanner.py`).
  - Anonymity layer: Tor proxy manager, MAC randomizer, DNS leak firewall rules, anti-forensics.
- **Live Boot Subsystem (`boot/`):**
  - Debian 12 Bookworm live-build scripts (`boot/live-build/`).
  - Forensic read-only drive mounter (`boot/scripts/mount-target-ro.sh`).
  - Hardware detection script (`boot/scripts/detect-hardware.sh`).
  - Console menu dashboard (`boot/scripts/redboot-menu.sh`).
  - ISO build automation (`scripts/build_iso.sh`).

---

## [0.1.0] — 2026-09-30

### Added
- Initial repository structure and directory layout
- Technical architecture document (`docs/architecture/ARCHITECTURE.md`)
- Project README with module overview and development phases
- MIT License with authorized-use notice
- Contributing guidelines (`CONTRIBUTING.md`)
- `.gitignore` for Python, Docker, and IDE files
- GitHub Actions CI workflow for linting and testing
- Core module with configuration loader, structured logger, and scope validator
