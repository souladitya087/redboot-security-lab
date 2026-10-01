"""
RedBoot System Security Auditor

Evaluates system configurations, user accounts, SUID binaries, sensitive file permissions,
and privilege escalation vectors. Can inspect both the live host and offline mounted filesystems
(critical for forensic assessment from bootable drives).
"""

from __future__ import annotations

import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from modules.core.logger import get_logger

# Known GTFOBins binaries that can be leveraged for privilege escalation if SUID
DANGEROUS_SUID_BINARIES = {
    "find",
    "vim",
    "vi",
    "bash",
    "sh",
    "dash",
    "cp",
    "mv",
    "nmap",
    "awk",
    "gawk",
    "less",
    "more",
    "nano",
    "python",
    "python3",
    "perl",
    "ruby",
    "lua",
    "tar",
    "zip",
    "env",
    "pkexec",
    "sudo",
    "su",
    "strace",
    "tcpdump",
    "wget",
    "curl",
    "tee",
    "chmod",
    "chown",
    "docker",
}

SENSITIVE_FILES = [
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
]


class SystemAuditor:
    """
    Performs security audits on Linux filesystems (live or mounted image).
    """

    def __init__(self, root_dir: str | Path = "/") -> None:
        self.root_dir = Path(root_dir)
        self.logger = get_logger("system-auditor")

    def _resolve(self, path: str) -> Path:
        """Resolve a path relative to the target root directory."""
        clean_path = path.lstrip("/")
        return self.root_dir / clean_path

    def audit_accounts(self) -> dict[str, Any]:
        """Audit user accounts in /etc/passwd."""
        passwd_file = self._resolve("/etc/passwd")
        users: list[dict[str, Any]] = []
        uid_zero_users: list[str] = []
        interactive_users: list[str] = []

        if not passwd_file.exists():
            return {
                "status": "not_found",
                "message": f"Passwd file not found at {passwd_file}",
                "users": [],
            }

        try:
            with open(passwd_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) >= 7:
                        username, _, uid, gid, comment, home, shell = parts[:7]
                        user_info = {
                            "username": username,
                            "uid": int(uid) if uid.isdigit() else uid,
                            "gid": int(gid) if gid.isdigit() else gid,
                            "home": home,
                            "shell": shell,
                        }
                        users.append(user_info)
                        if uid == "0":
                            uid_zero_users.append(username)
                        if not any(
                            shell.endswith(s) for s in ["nologin", "false", "sync"]
                        ):
                            interactive_users.append(username)
        except Exception as e:
            self.logger.error(f"Error reading passwd file: {e}")

        findings = []
        if len(uid_zero_users) > 1:
            findings.append(
                {
                    "severity": "CRITICAL",
                    "issue": "Multiple UID 0 Accounts Detected",
                    "details": f"Accounts with root privileges: {', '.join(uid_zero_users)}",
                }
            )

        return {
            "total_users": len(users),
            "uid_zero_accounts": uid_zero_users,
            "interactive_accounts": interactive_users,
            "findings": findings,
        }

    def audit_sensitive_files(self) -> list[dict[str, Any]]:
        """Audit permissions of sensitive configuration and credential files."""
        results: list[dict[str, Any]] = []
        for file_path in SENSITIVE_FILES:
            target = self._resolve(file_path)
            if not target.exists():
                continue

            try:
                st = target.stat()
                mode = st.st_mode
                perms = stat.filemode(mode)
                is_world_writable = bool(mode & stat.S_IWOTH)
                is_world_readable = bool(mode & stat.S_IROTH)

                finding: dict[str, Any] = {
                    "file": file_path,
                    "permissions": perms,
                    "world_writable": is_world_writable,
                    "world_readable": is_world_readable,
                    "severity": "INFO",
                }

                if file_path == "/etc/shadow" and (
                    is_world_readable or is_world_writable
                ):
                    finding["severity"] = "CRITICAL"
                    finding["issue"] = (
                        "Sensitive password hashes exposed to non-root users"
                    )
                elif file_path == "/etc/passwd" and is_world_writable:
                    finding["severity"] = "CRITICAL"
                    finding["issue"] = (
                        "/etc/passwd is world-writable (allows instant root account creation)"
                    )
                elif is_world_writable:
                    finding["severity"] = "HIGH"
                    finding["issue"] = f"{file_path} is world-writable"

                results.append(finding)
            except Exception as e:
                self.logger.error(f"Error inspecting {target}: {e}")

        return results

    def audit_suid_binaries(
        self, search_paths: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """Identify SUID/SGID binaries and flag known privilege escalation vectors."""
        if search_paths is None:
            search_paths = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin"]

        findings: list[dict[str, Any]] = []
        for base_path in search_paths:
            resolved_base = self._resolve(base_path)
            if not resolved_base.exists() or not resolved_base.is_dir():
                continue

            try:
                for entry in resolved_base.iterdir():
                    try:
                        if entry.is_file() and not entry.is_symlink():
                            st = entry.stat()
                            is_suid = bool(st.st_mode & stat.S_ISUID)
                            is_sgid = bool(st.st_mode & stat.S_ISGID)

                            if is_suid or is_sgid:
                                binary_name = entry.name.lower()
                                is_dangerous = binary_name in DANGEROUS_SUID_BINARIES
                                bin_rel = (
                                    entry.relative_to(self.root_dir)
                                    if self.root_dir != Path("/")
                                    else entry
                                )
                                findings.append(
                                    {
                                        "binary": str(bin_rel),
                                        "name": entry.name,
                                        "is_suid": is_suid,
                                        "is_sgid": is_sgid,
                                        "permissions": stat.filemode(st.st_mode),
                                        "is_known_gtfobin": is_dangerous,
                                        "severity": (
                                            "HIGH"
                                            if (is_suid and is_dangerous)
                                            else "LOW"
                                        ),
                                    }
                                )
                    except (PermissionError, FileNotFoundError):
                        continue
            except Exception as e:
                self.logger.error(f"Error scanning {resolved_base} for SUID: {e}")

        return findings

    def run_full_audit(self) -> dict[str, Any]:
        """Run complete system configuration and posture assessment."""
        timestamp = datetime.now(timezone.utc).isoformat()
        accounts = self.audit_accounts()
        files = self.audit_sensitive_files()
        suid = self.audit_suid_binaries()

        critical_count = sum(1 for f in files if f.get("severity") == "CRITICAL")
        critical_count += len(accounts.get("findings", []))
        high_count = sum(1 for s in suid if s.get("severity") == "HIGH")
        high_count += sum(1 for f in files if f.get("severity") == "HIGH")

        return {
            "module": "system_assessment",
            "timestamp": timestamp,
            "target_root": str(self.root_dir),
            "summary": {
                "critical_issues": critical_count,
                "high_issues": high_count,
                "suid_binaries_found": len(suid),
                "sensitive_files_checked": len(files),
            },
            "findings": {
                "accounts": accounts,
                "file_security": files,
                "suid_binaries": suid,
            },
        }
