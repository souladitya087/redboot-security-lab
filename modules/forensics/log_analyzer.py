"""
RedBoot Forensic Log Correlation & Anomaly Detector

Parses Linux authentication and system logs (auth.log, syslog, secure) to detect
brute-force attacks, root escalation, and anomalous behavior.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from modules.core.logger import get_logger

# Signatures for forensic log detection
SSH_FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)"
)
SSH_ACCEPTED_PATTERN = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)"
)
SUDO_COMMAND_PATTERN = re.compile(r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)")
SU_ATTEMPT_PATTERN = re.compile(r"su(?:\[\d+\])?: \+ (?:\S+) (\S+):(\S+)")


class LogAnalyzer:
    """Analyzes system and auth logs for forensic incident investigation."""

    def __init__(self) -> None:
        self.logger = get_logger("forensic-log-analyzer")

    def analyze_auth_log(self, log_path: str | Path) -> dict[str, Any]:
        """Parse authentication log and return correlated findings."""
        lp = Path(log_path)
        if not lp.exists():
            return {
                "status": "not_found",
                "message": f"Log file not found at {lp}",
                "findings": [],
            }

        failed_logins: dict[str, int] = {}
        successful_logins: list[dict[str, str]] = []
        sudo_executions: list[dict[str, str]] = []
        total_lines = 0

        with open(lp, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                total_lines += 1
                line = line.strip()

                # Check failed SSH logins
                m_fail = SSH_FAILED_PATTERN.search(line)
                if m_fail:
                    user, ip, _ = m_fail.groups()
                    key = f"{user}@{ip}"
                    failed_logins[key] = failed_logins.get(key, 0) + 1

                # Check accepted SSH logins
                m_accept = SSH_ACCEPTED_PATTERN.search(line)
                if m_accept:
                    user, ip, port = m_accept.groups()
                    successful_logins.append(
                        {
                            "user": user,
                            "source_ip": ip,
                            "port": port,
                            "raw": line,
                        }
                    )

                # Check sudo commands
                m_sudo = SUDO_COMMAND_PATTERN.search(line)
                if m_sudo:
                    user, command = m_sudo.groups()
                    sudo_executions.append(
                        {
                            "user": user,
                            "command": command.strip(),
                            "raw": line,
                        }
                    )

        # Identify potential brute-force sources (>= 5 failures)
        brute_force_alerts = []
        for target_ip, count in failed_logins.items():
            if count >= 5:
                brute_force_alerts.append(
                    {
                        "severity": "HIGH",
                        "issue": "SSH Password Brute-Force Activity Detected",
                        "target": target_ip,
                        "failed_attempts": count,
                    }
                )

        return {
            "log_file": str(lp),
            "lines_parsed": total_lines,
            "failed_attempts_by_origin": failed_logins,
            "brute_force_alerts": brute_force_alerts,
            "successful_logins": successful_logins,
            "sudo_executions": sudo_executions,
        }

    def correlate_logs(self, log_paths: list[str | Path]) -> dict[str, Any]:
        """Aggregate analysis across multiple log files."""
        timestamp = datetime.now(timezone.utc).isoformat()
        results: list[dict[str, Any]] = []

        for p in log_paths:
            res = self.analyze_auth_log(p)
            results.append(res)

        total_alerts = sum(len(r.get("brute_force_alerts", [])) for r in results)

        return {
            "module": "forensics_log_correlation",
            "timestamp": timestamp,
            "logs_analyzed": len(log_paths),
            "total_alerts": total_alerts,
            "details": results,
        }
