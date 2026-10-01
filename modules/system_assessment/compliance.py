"""
RedBoot Compliance and Hardening Evaluator

Calculates security compliance scores and evaluates hardening posture
based on standard security benchmarks.
"""

from __future__ import annotations

from typing import Any


class ComplianceEvaluator:
    """Evaluates benchmark rules and calculates overall compliance score."""

    @staticmethod
    def evaluate(audit_results: dict[str, Any]) -> dict[str, Any]:
        """
        Evaluate system assessment audit results against standard hardening rules.
        Returns a compliance breakdown and score between 0% and 100%.
        """
        checks: list[dict[str, Any]] = []

        # Check 1: No extra UID 0 accounts
        accounts = audit_results.get("findings", {}).get("accounts", {})
        uid_zeros = accounts.get("uid_zero_accounts", [])
        passed_uid0 = len(uid_zeros) <= 1
        checks.append(
            {
                "id": "SEC-01",
                "name": "Single Root Account Enforcement",
                "category": "Account Security",
                "status": "PASS" if passed_uid0 else "FAIL",
                "weight": 25,
                "remediation": "Remove or change UID for unauthorized accounts with UID 0.",
            }
        )

        # Check 2: Sensitive files not world-writable
        files = audit_results.get("findings", {}).get("file_security", [])
        ww_files = [f["file"] for f in files if f.get("world_writable")]
        passed_ww = len(ww_files) == 0
        checks.append(
            {
                "id": "SEC-02",
                "name": "Sensitive Files Access Control",
                "category": "File Integrity",
                "status": "PASS" if passed_ww else "FAIL",
                "weight": 25,
                "remediation": f"Ensure files {ww_files} are not world-writable (e.g. chmod 600 /etc/shadow).",
            }
        )

        # Check 3: Shadow file read protection
        shadow_audit = next((f for f in files if f.get("file") == "/etc/shadow"), None)
        passed_shadow = not (shadow_audit and shadow_audit.get("world_readable"))
        checks.append(
            {
                "id": "SEC-03",
                "name": "Password Hash Confidentiality",
                "category": "Credential Security",
                "status": "PASS" if passed_shadow else "FAIL",
                "weight": 25,
                "remediation": "Restrict /etc/shadow read access to root only (chmod 000 or 600).",
            }
        )

        # Check 4: No GTFOBins SUID binaries
        suid = audit_results.get("findings", {}).get("suid_binaries", [])
        dangerous_suid = [s["name"] for s in suid if s.get("is_known_gtfobin")]
        passed_suid = len(dangerous_suid) == 0
        checks.append(
            {
                "id": "SEC-04",
                "name": "SUID Binary Privilege Escalation Prevention",
                "category": "Privilege Control",
                "status": "PASS" if passed_suid else "FAIL",
                "weight": 25,
                "remediation": f"Remove SUID bit from binaries: {', '.join(dangerous_suid)}.",
            }
        )

        # Calculate score
        total_weight = sum(c["weight"] for c in checks)
        passed_weight = sum(c["weight"] for c in checks if c["status"] == "PASS")
        score_percent = (
            round((passed_weight / total_weight) * 100, 1) if total_weight > 0 else 0.0
        )

        if score_percent >= 80:
            rating = "GOOD"
        elif score_percent >= 50:
            rating = "MODERATE"
        else:
            rating = "CRITICAL_RISK"

        return {
            "score": score_percent,
            "rating": rating,
            "checks_passed": sum(1 for c in checks if c["status"] == "PASS"),
            "checks_total": len(checks),
            "checks": checks,
        }
