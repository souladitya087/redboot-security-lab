"""
Unit tests for Reporting Engine and Formatters.
"""

from __future__ import annotations

import json
from pathlib import Path

from reporting.engine import ReportData, ReportEngine
from reporting.formatters.html_formatter import HTMLFormatter
from reporting.formatters.json_formatter import JSONFormatter
from reporting.formatters.markdown_formatter import MarkdownFormatter


class TestReportingEngine:
    def test_executive_summary_calculation(self):
        data = ReportData(
            reconnaissance={
                "findings": [
                    {
                        "ip": "192.168.56.10",
                        "findings": [{"port": 22, "service": "ssh"}],
                    }
                ]
            },
            vulnerabilities={
                "summary": {
                    "total_vulnerabilities": 1,
                    "severity_distribution": {
                        "CRITICAL": 1,
                        "HIGH": 0,
                        "MEDIUM": 0,
                        "LOW": 0,
                        "INFORMATIONAL": 0,
                    },
                },
                "findings": [
                    {
                        "host": "192.168.56.10",
                        "port": 21,
                        "cve_id": "CVE-2011-2523",
                        "severity": "CRITICAL",
                        "title": "vsftpd backdoor",
                        "cvss_score": 9.8,
                    }
                ],
            },
            evidence=[{"evidence_id": "EVD-001", "file_name": "capture.pcap", "file_size": 1024}],
        )

        engine = ReportEngine(data)
        summary = engine.calculate_executive_summary()

        assert summary["overall_posture"] == "CRITICAL_RISK"
        assert summary["total_hosts_surveyed"] == 1
        assert summary["critical_vulnerabilities"] == 1
        assert summary["total_evidence_collected"] == 1

    def test_markdown_formatter_output(self):
        data = ReportData(case_id="CASE-UNIT-01")
        engine = ReportEngine(data)
        engine.calculate_executive_summary()

        md = MarkdownFormatter.format_report(engine.data)
        assert "# RedBoot Security Assessment & Forensic Report" in md
        assert "CASE-UNIT-01" in md
        assert "Executive Summary" in md

    def test_json_formatter_output(self):
        data = ReportData(case_id="CASE-JSON-01")
        raw_json = JSONFormatter.format_report(data)
        parsed = json.loads(raw_json)
        assert parsed["case_id"] == "CASE-JSON-01"

    def test_html_formatter_output(self):
        data = ReportData(case_id="CASE-HTML-01")
        engine = ReportEngine(data)
        engine.calculate_executive_summary()

        html = HTMLFormatter.format_report(engine.data)
        assert "<!DOCTYPE html>" in html
        assert "CASE-HTML-01" in html
        assert "Security Posture" in html

    def test_from_directory_loader(self, tmp_path: Path):
        recon_file = tmp_path / "recon.json"
        recon_file.write_text(
            json.dumps({"module": "reconnaissance", "findings": [{"ip": "10.0.0.5", "findings": []}]}),
            encoding="utf-8",
        )

        engine = ReportEngine.from_directory(tmp_path, case_id="CASE-DIR-01")
        assert engine.data.case_id == "CASE-DIR-01"
        assert len(engine.data.reconnaissance.get("findings", [])) == 1
