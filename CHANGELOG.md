# Changelog

All notable changes to the RedBoot project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- Module scaffolding with `__init__.py` files:
  - `modules/core/` — shared configuration, logging, scope validation
  - `modules/reconnaissance/`
  - `modules/system_assessment/`
  - `modules/vulnerability_assessment/`
  - `modules/anonymity/`
  - `modules/forensics/`
  - `modules/evidence/`
- `reporting/` directory scaffolding
- `lab/` directory with Docker and scenario subdirectories
- `tests/` directory with unit and integration subdirectories
- Core module with configuration loader, structured logger, and scope validator
