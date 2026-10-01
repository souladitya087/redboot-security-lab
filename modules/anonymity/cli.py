"""
CLI Entrypoint for RedBoot Anonymity / Non-Traceability Module
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from modules.anonymity.anti_forensics import AntiForensicsAuditor
from modules.anonymity.leak_prevention import DNSLeakPrevention
from modules.anonymity.mac_manager import MACManager
from modules.anonymity.proxy_manager import ProxyManager
from modules.core.logger import get_logger


@click.command(name="redboot-anonymity")
@click.option(
    "--check-all",
    is_flag=True,
    default=True,
    help="Perform full anonymity and anti-forensics audit.",
)
@click.option(
    "--randomize-mac",
    default=None,
    help="Generate spoofing plan for specified interface (e.g. eth0).",
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Output JSON file path.",
)
def main(check_all: bool, randomize_mac: str | None, output: str | None) -> None:
    """Audit anonymity, proxy routing, and volatile posture."""
    logger = get_logger("anonymity-cli")
    try:
        report: dict[str, object] = {
            "module": "anonymity",
        }

        if randomize_mac:
            mac_mgr = MACManager()
            report["mac_plan"] = mac_mgr.create_spoof_plan(randomize_mac)

        if check_all:
            proxy_mgr = ProxyManager()
            report["proxy"] = proxy_mgr.verify_anonymity_status()

            leak_prev = DNSLeakPrevention()
            report["dns_leak"] = leak_prev.audit_leak_defense_posture()

            anti_for = AntiForensicsAuditor()
            report["anti_forensics"] = anti_for.run_environment_audit()

        formatted_json = json.dumps(report, indent=2)
        click.echo(formatted_json)

        if output:
            out_path = Path(output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(formatted_json, encoding="utf-8")
            logger.info(f"Anonymity audit results saved to {output}")

    except Exception as e:
        logger.error(f"Anonymity audit error: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
