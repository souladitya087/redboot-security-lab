"""
RedBoot Reporting Engine

Aggregates assessment and forensic outputs from all modules into a unified data model.
Computes executive summaries, risk posture metrics, and chains of custody.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from modules.core.logger import get_logger


@dataclass
class ReportData:
    title: str = "RedBoot Security Assessment & Forensic Report"
    case_id: str = "CASE-DEFAULT"
    operator: str = "lab-user"
    lab_name: str = "RedBoot Academic Security Lab"
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    scope: dict[str, Any] = field(default_factory=dict)
    reconnaissance: dict[str, Any] = field(default_factory=dict)
    vulnerabilities: dict[str, Any] = field(default_factory=dict)
    system_assessment: dict[str, Any] = field(default_factory=dict)
    forensics: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    custody_entries: list[dict[str, Any]] = field(default_factory=list)
    executive_summary: dict[str, Any] = field(default_factory=dict)


class ReportEngine:
    """Consolidates security findings and builds comprehensive assessment deliverables."""

    def __init__(self, data: ReportData | None = None) -> None:
        self.data = data or ReportData()
        self.logger = get_logger("report-engine")

    @classmethod
    def from_directory(
        cls, output_dir: str | Path, case_id: str = "CASE-DEFAULT"
    ) -> "ReportEngine":
        """
        Build report data by automatically reading generated JSON artifacts in output directory.
        """
        out = Path(output_dir)
        report_data = ReportData(case_id=case_id)

        # Look for reconnaissance output
        for p in [out / "recon.json", out / "reconnaissance.json"]:
            if p.exists():
                try:
                    report_data.reconnaissance = json.loads(
                        p.read_text(encoding="utf-8")
                    )
                    break
                except Exception:
                    pass

        # Look for vulnerability assessment output
        for p in [out / "vuln.json", out / "vulnerabilities.json"]:
            if p.exists():
                try:
                    report_data.vulnerabilities = json.loads(
                        p.read_text(encoding="utf-8")
                    )
                    break
                except Exception:
                    pass

        # Look for system assessment output
        for p in [out / "system.json", out / "system_audit.json"]:
            if p.exists():
                try:
                    report_data.system_assessment = json.loads(
                        p.read_text(encoding="utf-8")
                    )
                    break
                except Exception:
                    pass

        # Look for evidence and custody records
        vault_dir = out / "evidence_vault"
        if not vault_dir.exists():
            vault_dir = out

        custody_file = vault_dir / "chain_of_custody.json"
        if custody_file.exists():
            try:
                report_data.custody_entries = json.loads(
                    custody_file.read_text(encoding="utf-8")
                )
            except Exception:
                pass

        for meta_file in sorted(vault_dir.glob("EVD-*/metadata.json")):
            try:
                report_data.evidence.append(
                    json.loads(meta_file.read_text(encoding="utf-8"))
                )
            except Exception:
                pass

        engine = cls(report_data)
        engine.calculate_executive_summary()
        return engine

    def calculate_executive_summary(self) -> dict[str, Any]:
        """Compute aggregate risk rating, hosts surveyed, and vulnerability breakdown."""
        vuln_summary = self.data.vulnerabilities.get("summary", {})
        sev_dist = vuln_summary.get(
            "severity_distribution",
            {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0},
        )

        critical_count = sev_dist.get("CRITICAL", 0)
        high_count = sev_dist.get("HIGH", 0)

        # Consider system assessment findings
        sys_summary = self.data.system_assessment.get("summary", {})
        critical_count += sys_summary.get("critical_issues", 0)
        high_count += sys_summary.get("high_issues", 0)

        if critical_count > 0:
            posture = "CRITICAL_RISK"
        elif high_count > 0:
            posture = "ELEVATED_RISK"
        elif vuln_summary.get("total_vulnerabilities", 0) > 0:
            posture = "MODERATE_RISK"
        else:
            posture = "LOW_RISK"

        hosts_count = len(self.data.reconnaissance.get("findings", []))
        total_evidence = len(self.data.evidence)

        summary = {
            "overall_posture": posture,
            "total_hosts_surveyed": hosts_count,
            "critical_vulnerabilities": critical_count,
            "high_vulnerabilities": high_count,
            "total_evidence_collected": total_evidence,
            "chain_of_custody_entries": len(self.data.custody_entries),
        }
        self.data.executive_summary = summary
        return summary
