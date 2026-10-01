"""
RedBoot Markdown Report Formatter
"""

from __future__ import annotations

from reporting.engine import ReportData


class MarkdownFormatter:
    """Formats ReportData into publication-ready GitHub-flavored Markdown."""

    @staticmethod
    def format_report(data: ReportData) -> str:
        lines: list[str] = [
            f"# {data.title}",
            "",
            f"> **Case ID:** `{data.case_id}`  ",
            f"> **Lab:** {data.lab_name}  ",
            f"> **Operator:** `{data.operator}`  ",
            f"> **Generated:** {data.generated_at}  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            f"- **Overall Risk Posture:** **`{data.executive_summary.get('overall_posture', 'UNKNOWN')}`**",
            f"- **Hosts Surveyed:** {data.executive_summary.get('total_hosts_surveyed', 0)}",
            f"- **Critical Severity Issues:** {data.executive_summary.get('critical_vulnerabilities', 0)}",
            f"- **High Severity Issues:** {data.executive_summary.get('high_vulnerabilities', 0)}",
            f"- **Total Forensic Evidence Items:** {data.executive_summary.get('total_evidence_collected', 0)}",
            (
                "- **Chain of Custody Events:** "
                f"{data.executive_summary.get('chain_of_custody_entries', 0)}"
            ),
            "",
            "---",
            "",
            "## 2. Reconnaissance & Network Discovery",
            "",
        ]

        recon_findings = data.reconnaissance.get("findings", [])
        if not recon_findings:
            lines.append("*No active hosts or open ports recorded.*")
        else:
            lines.extend(
                [
                    "| Host IP / Target | Open Ports | Services |",
                    "|---|---|---|",
                ]
            )
            for host_entry in recon_findings:
                target = host_entry.get("ip") or host_entry.get("target", "unknown")
                ports = [str(p.get("port")) for p in host_entry.get("findings", [])]
                services = [
                    p.get("service", "unknown") for p in host_entry.get("findings", [])
                ]
                lines.append(
                    f"| `{target}` | {', '.join(ports)} | {', '.join(services)} |"
                )

        lines.extend(
            [
                "",
                "---",
                "",
                "## 3. Vulnerability Findings",
                "",
            ]
        )

        vuln_findings = data.vulnerabilities.get("findings", [])
        if not vuln_findings:
            lines.append("*No vulnerabilities detected.*")
        else:
            lines.extend(
                [
                    "| Severity | CVE / Identifier | Target | Title | CVSS | Exploit? |",
                    "|---|---|---|---|---|---|",
                ]
            )
            for v in vuln_findings:
                sev = v.get("severity", "INFO")
                cve = v.get("cve_id", "N/A")
                host = f"{v.get('host')}:{v.get('port')}"
                title = v.get("title", "")
                cvss = v.get("cvss_score", 0.0)
                exp = "⚠️ Yes" if v.get("exploit_available") else "No"
                lines.append(
                    f"| **{sev}** | `{cve}` | `{host}` | {title} | {cvss} | {exp} |"
                )

        lines.extend(
            [
                "",
                "---",
                "",
                "## 4. Digital Evidence & Chain of Custody Appendix",
                "",
            ]
        )

        if not data.evidence:
            lines.append("*No digital evidence artifacts archived.*")
        else:
            lines.extend(
                [
                    "| Evidence ID | File Name | Size (Bytes) | SHA-256 Fingerprint | Custodian |",
                    "|---|---|---|---|---|",
                ]
            )
            for ev in data.evidence:
                eid = ev.get("evidence_id", "N/A")
                fname = ev.get("file_name", "N/A")
                size = ev.get("file_size", 0)
                sha = ev.get("sha256", "N/A")[:16] + "..."
                cust = ev.get("custodian", "N/A")
                lines.append(f"| `{eid}` | `{fname}` | {size} | `{sha}` | `{cust}` |")

        lines.extend(
            [
                "",
                "---",
                "",
                "*End of RedBoot Assessment Report. Generated automatically with forensic integrity verification.*",
                "",
            ]
        )

        return "\n".join(lines)
