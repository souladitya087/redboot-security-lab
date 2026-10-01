"""
CLI Entrypoint for RedBoot Digital Forensics Module
"""

from __future__ import annotations

import json
import sys

import click

from modules.core.logger import get_logger
from modules.forensics.carver import FileCarver
from modules.forensics.imager import ForensicImager
from modules.forensics.log_analyzer import LogAnalyzer
from modules.forensics.timeline import TimelineGenerator


@click.group(name="redboot-forensics")
def cli() -> None:
    """Digital Forensics toolkit for disk imaging, carving, and analysis."""
    pass


@cli.command(name="acquire")
@click.option("--source", "-s", required=True, help="Source path or device to acquire.")
@click.option("--output", "-o", required=True, help="Destination raw image file.")
@click.option("--case", default="CASE-001", help="Case identifier.")
@click.option("--examiner", default="examiner", help="Examiner name.")
def acquire(source: str, output: str, case: str, examiner: str) -> None:
    """Perform bit-for-bit forensic image acquisition with SHA-256 hashing."""
    logger = get_logger("forensics-cli")
    try:
        imager = ForensicImager()
        res = imager.acquire_image(source, output, case_id=case, examiner=examiner)
        click.echo(json.dumps(res, indent=2))
    except Exception as e:
        logger.error(f"Image acquisition failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command(name="carve")
@click.option("--image", "-i", required=True, help="Path to raw image or disk binary.")
@click.option(
    "--output-dir", "-o", required=True, help="Directory to save carved files."
)
def carve(image: str, output_dir: str) -> None:
    """Carve files from disk images using magic byte signatures."""
    logger = get_logger("forensics-cli")
    try:
        carver = FileCarver()
        findings = carver.carve_file(image, output_dir)
        click.echo(
            json.dumps({"carved_count": len(findings), "files": findings}, indent=2)
        )
    except Exception as e:
        logger.error(f"Carving failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command(name="timeline")
@click.option(
    "--target-dir", "-t", required=True, help="Directory or mount point to inspect."
)
@click.option("--csv-output", "-c", default=None, help="Path to save timeline CSV.")
def timeline(target_dir: str, csv_output: str | None) -> None:
    """Generate MACB filesystem timeline."""
    logger = get_logger("forensics-cli")
    try:
        tg = TimelineGenerator()
        events = tg.generate_timeline(target_dir)
        if csv_output:
            tg.export_csv(events, csv_output)
            click.echo(f"Timeline exported to {csv_output} ({len(events)} events)")
        else:
            click.echo(
                json.dumps(
                    {"total_events": len(events), "sample": events[:20]}, indent=2
                )
            )
    except Exception as e:
        logger.error(f"Timeline creation failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command(name="analyze-logs")
@click.option(
    "--log-file",
    "-l",
    required=True,
    multiple=True,
    help="Log file path(s) to analyze.",
)
def analyze_logs(log_file: tuple[str, ...]) -> None:
    """Correlate auth and system logs for suspicious activity."""
    logger = get_logger("forensics-cli")
    try:
        analyzer = LogAnalyzer()
        res = analyzer.correlate_logs(list(log_file))
        click.echo(json.dumps(res, indent=2))
    except Exception as e:
        logger.error(f"Log analysis failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    cli()
