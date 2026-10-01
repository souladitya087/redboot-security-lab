# Changelog

All notable changes to the RedBoot project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.5.0] — 2026-10-01

### Added
- **Phase 2 (Bootable Environment):**
  - Debian 12 Bookworm live-build configuration (`boot/live-build/`) with `noautomount`, `noswap`, `ro`, and `toram` boot parameters.
  - Package lists for forensic and security assessment tooling (`sleuthkit`, `testdisk`, `ddrescue`, `tor`, `macchanger`).
  - Chroot setup hook with user provisioning, udev write-block protection rules, and kernel hardening.
  - Custom multi-boot GRUB menu configuration.
  - Safe forensic read-only mounter script (`boot/scripts/mount-target-ro.sh`).
  - Hardware and network discovery script (`boot/scripts/detect-hardware.sh`).
  - Interactive console dashboard menu (`boot/scripts/redboot-menu.sh`).
  - Live ISO automated build script (`scripts/build_iso.sh`).
- **Phase 3 (Assessment Engine):**
  - Reconnaissance module: Scope-enforced concurrent port scanner, banner grabber, DNS enumerator, OS fingerprinter, and CLI.
  - System assessment module: Live and offline mounted filesystem auditor, account security analyzer, SUID/GTFOBins evaluator, and CIS-inspired compliance scoring.
  - Vulnerability assessment module: Curated CVE database, regex banner matching, cleartext protocol detection, and CVSS v3.1 risk scorer.
  - Anonymity module: SOCKS5/Tor proxy configuration helper, locally-administered MAC randomizer, DNS leak firewall rule generator, and anti-forensics volatile memory auditor.
- **Phase 4 (Forensics & Evidence Collection):**
  - Digital forensics module: Bit-for-bit raw disk imager with simultaneous SHA-256 and MD5 hashing, magic-byte file carver (PNG, JPG, PDF, ZIP, ELF, SQLite), MACB timeline generator, and authentication log correlation analyzer.
  - Evidence collection module: Cryptographically-chained append-only custody ledger, automated evidence vault ingestion with dual hashing, and integrity verifier.
- **Phase 5 (Reporting Engine):**
  - Unified `ReportEngine` aggregating multi-module findings.
  - Dark-mode responsive HTML dashboard report template.
  - Publication-ready Markdown report formatter.
  - Machine-readable JSON export formatter and reporting CLI.
- **Documentation & Tracking:**
  - Added `docs/PROJECT_STATUS.md` tracking overall project progress, metrics, and roadmap.
  - Expanded unit test suite to 57 passing tests.

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
- Module scaffolding with `__init__.py` files
- Core module with configuration loader, structured logger, and scope validator
