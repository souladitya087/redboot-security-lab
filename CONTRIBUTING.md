# Contributing to RedBoot

Thank you for your interest in contributing to RedBoot. This document provides guidelines for contributing to the project.

---

## Code of Conduct

All contributors must use this project **only** for authorized academic and laboratory purposes. Any contribution that facilitates unauthorized access to systems is prohibited and will be rejected.

---

## How to Contribute

### 1. Fork & Branch

```bash
git checkout -b feature/your-feature-name
```

Use the following branch naming conventions:

| Prefix | Purpose |
|---|---|
| `feature/` | New functionality |
| `fix/` | Bug fixes |
| `docs/` | Documentation updates |
| `test/` | Test additions or improvements |
| `lab/` | Lab scenario additions |

### 2. Code Standards

- **Language:** Python 3.11+ for all modules
- **Style:** PEP 8 compliant; use `black` for formatting, `flake8` for linting
- **Type hints:** Required for all public functions
- **Docstrings:** Google-style docstrings for all modules, classes, and public functions
- **Testing:** All new functionality must include unit tests (pytest)

### 3. Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(recon): add service enumeration scanner
fix(evidence): correct SHA-256 hash computation for large files
docs(architecture): update data flow diagram
test(forensics): add disk image parsing tests
```

### 4. Pull Requests

1. Ensure all tests pass: `python -m pytest tests/ -v`
2. Ensure code is formatted: `black --check .`
3. Ensure linting passes: `flake8 .`
4. Write a clear PR description explaining what and why
5. Reference any related issues

### 5. Module Development

When adding a new module or extending an existing one:

1. Follow the directory structure defined in [ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md)
2. Include a module-level `README.md`
3. Define clear input/output interfaces (JSON)
4. Add both unit and integration tests
5. Update the top-level `README.md` if the module list changes

---

## Reporting Issues

Use GitHub Issues with the following labels:

- `bug` — Something is broken
- `enhancement` — New feature request
- `documentation` — Documentation improvements
- `lab-scenario` — New lab scenario proposal
- `question` — General questions

---

## Ethical Guidelines

- All code must enforce scope validation
- Forensic tools must operate in read-only mode on evidence
- Lab scenarios must be self-contained and network-isolated
- Documentation must include appropriate warnings about authorized use
