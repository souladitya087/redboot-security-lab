#!/usr/bin/env python3
"""
RedBoot — Unified Security Assessment & Forensic CLI

Entry point providing unified command-line access to all RedBoot platform capabilities:
reconnaissance, system auditing, vulnerability scanning, anonymity, digital forensics,
evidence collection, scenario execution, and report generation.

Authorized laboratory use only.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from modules.anonymity.cli import main as anonymity_cmd  # noqa: E402
from modules.evidence.cli import cli as evidence_group  # noqa: E402
from modules.forensics.cli import cli as forensics_group  # noqa: E402
from modules.reconnaissance.cli import main as recon_cmd  # noqa: E402
from modules.system_assessment.cli import main as audit_cmd  # noqa: E402
from modules.vulnerability_assessment.cli import main as vuln_cmd  # noqa: E402
from reporting.cli import main as report_cmd  # noqa: E402
from scripts.run_scenario import main as scenario_cmd  # noqa: E402


@click.group(name="redboot")
@click.version_option(version="1.0.0", prog_name="RedBoot Security Platform")
def cli() -> None:
    """RedBoot — Bootable Security Assessment & Forensic Analysis Platform."""
    pass


# Register module commands and groups
cli.add_command(recon_cmd, name="recon")
cli.add_command(audit_cmd, name="audit")
cli.add_command(vuln_cmd, name="vuln")
cli.add_command(anonymity_cmd, name="anonymity")
cli.add_command(forensics_group, name="forensics")
cli.add_command(evidence_group, name="evidence")
cli.add_command(report_cmd, name="report")
cli.add_command(scenario_cmd, name="scenario")


@cli.command(name="status")
def status_cmd() -> None:
    """Display platform component status, version, and active safeguards."""
    click.echo("=================================================================")
    click.echo("  RedBoot — Security Assessment & Forensic Platform (v1.0.0)")
    click.echo("  Authorized Isolated Laboratory Use Only")
    click.echo("=================================================================")
    click.echo("  Core Engine:               ONLINE (Scope enforcement active)")
    click.echo("  Reconnaissance Module:     AVAILABLE (TCP / DNS / Fingerprint)")
    click.echo("  System Assessment Module:  AVAILABLE (Auditor / CIS Benchmark)")
    click.echo("  Vulnerability Module:      AVAILABLE (CVE Catalog / CVSS v3.1)")
    click.echo("  Anonymity Layer:           AVAILABLE (Tor SOCKS5 / MAC Spoof)")
    click.echo("  Digital Forensics Module:  AVAILABLE (Imager / Carver / Timeline)")
    click.echo("  Evidence Vault & Ledger:   AVAILABLE (Append-Only SHA-256 Chain)")
    click.echo("  Reporting Engine:          AVAILABLE (HTML / Markdown / JSON)")
    click.echo("=================================================================")


if __name__ == "__main__":
    cli()
