"""
CLI Entrypoint for RedBoot Digital Evidence Collection Module
"""

from __future__ import annotations

import json
import sys

import click

from modules.core.logger import get_logger
from modules.evidence.collector import EvidenceCollector
from modules.evidence.verifier import EvidenceVerifier


@click.group(name="redboot-evidence")
def cli() -> None:
    """Evidence Collection and Chain of Custody Management."""
    pass


@cli.command(name="collect")
@click.option(
    "--file", "-f", "source_file", required=True, help="Path to evidence artifact file."
)
@click.option(
    "--desc", "-d", "description", required=True, help="Description of evidence."
)
@click.option(
    "--custodian", "-c", default="operator", help="Custodian / Investigator name."
)
@click.option("--case", default="CASE-001", help="Case identifier.")
@click.option("--vault", default="evidence_vault", help="Path to evidence vault.")
def collect_evidence(
    source_file: str, description: str, custodian: str, case: str, vault: str
) -> None:
    """Collect an artifact into the vault and record in chain of custody."""
    logger = get_logger("evidence-cli")
    try:
        collector = EvidenceCollector(vault_dir=vault)
        meta = collector.collect(
            source_file=source_file,
            description=description,
            custodian=custodian,
            case_id=case,
        )
        click.echo(json.dumps(meta, indent=2))
    except Exception as e:
        logger.error(f"Collection failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command(name="verify")
@click.option("--vault", "-v", default="evidence_vault", help="Path to evidence vault.")
def verify_vault(vault: str) -> None:
    """Verify integrity of all files and the chain of custody ledger."""
    logger = get_logger("evidence-cli")
    try:
        verifier = EvidenceVerifier(vault_dir=vault)
        res = verifier.verify_vault()
        click.echo(json.dumps(res, indent=2))
        if not res["overall_integrity_verified"]:
            sys.exit(2)
    except Exception as e:
        logger.error(f"Verification error: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command(name="list")
@click.option("--vault", "-v", default="evidence_vault", help="Path to evidence vault.")
def list_vault(vault: str) -> None:
    """List all registered items in the evidence vault."""
    collector = EvidenceCollector(vault_dir=vault)
    items = collector.list_evidence()
    click.echo(json.dumps(items, indent=2))


if __name__ == "__main__":
    cli()
