"""
CLI Entrypoint for RedBoot Reporting Engine
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from modules.core.logger import get_logger
from reporting.engine import ReportEngine
from reporting.formatters.html_formatter import HTMLFormatter
from reporting.formatters.json_formatter import JSONFormatter
from reporting.formatters.markdown_formatter import MarkdownFormatter


@click.command(name="redboot-report")
@click.option(
    "--input-dir",
    "-i",
    required=True,
    help="Directory containing assessment JSON outputs and evidence vault.",
)
@click.option(
    "--output-dir",
    "-o",
    default=None,
    help="Directory to save generated reports (defaults to input-dir).",
)
@click.option(
    "--case",
    default="CASE-001",
    help="Case identifier.",
)
@click.option(
    "--format",
    "-f",
    "export_format",
    type=click.Choice(["all", "html", "json", "markdown"], case_sensitive=False),
    default="all",
    help="Format to export.",
)
def main(input_dir: str, output_dir: str | None, case: str, export_format: str) -> None:
    """Generate professional assessment and forensic reports."""
    logger = get_logger("reporting-cli")
    try:
        in_path = Path(input_dir)
        if not in_path.exists():
            click.echo(f"Error: Input directory {input_dir} does not exist.", err=True)
            sys.exit(1)

        out_path = Path(output_dir) if output_dir else in_path
        out_path.mkdir(parents=True, exist_ok=True)

        engine = ReportEngine.from_directory(in_path, case_id=case)
        fmt = export_format.lower()

        if fmt in ["all", "html"]:
            html_text = HTMLFormatter.format_report(engine.data)
            html_file = out_path / "report.html"
            html_file.write_text(html_text, encoding="utf-8")
            logger.info(f"HTML report written to {html_file}")
            click.echo(f"[+] HTML report: {html_file}")

        if fmt in ["all", "markdown"]:
            md_text = MarkdownFormatter.format_report(engine.data)
            md_file = out_path / "report.md"
            md_file.write_text(md_text, encoding="utf-8")
            logger.info(f"Markdown report written to {md_file}")
            click.echo(f"[+] Markdown report: {md_file}")

        if fmt in ["all", "json"]:
            json_text = JSONFormatter.format_report(engine.data)
            json_file = out_path / "report.json"
            json_file.write_text(json_text, encoding="utf-8")
            logger.info(f"JSON report written to {json_file}")
            click.echo(f"[+] JSON report: {json_file}")

    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
