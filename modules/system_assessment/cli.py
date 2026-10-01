"""
CLI Entrypoint for RedBoot System Assessment Module
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from modules.core.logger import get_logger
from modules.system_assessment.auditor import SystemAuditor
from modules.system_assessment.compliance import ComplianceEvaluator


@click.command(name="redboot-system-audit")
@click.option(
    "--root-dir",
    "-r",
    default="/",
    help="Target root filesystem directory (e.g. '/' or '/mnt/target').",
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Output JSON file path.",
)
@click.option(
    "--compliance",
    is_flag=True,
    default=False,
    help="Include CIS-style compliance evaluation scoring.",
)
def main(root_dir: str, output: str | None, compliance: bool) -> None:
    """Audit system security configuration and posture."""
    logger = get_logger("system-assessment-cli")
    try:
        auditor = SystemAuditor(root_dir=root_dir)
        results = auditor.run_full_audit()

        if compliance:
            eval_res = ComplianceEvaluator.evaluate(results)
            results["compliance"] = eval_res

        formatted_json = json.dumps(results, indent=2)
        click.echo(formatted_json)

        if output:
            out_path = Path(output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(formatted_json, encoding="utf-8")
            logger.info(f"System assessment results saved to {output}")

    except Exception as e:
        logger.error(f"System audit error: {e}")
        click.echo(f"System audit error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
