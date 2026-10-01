"""
RedBoot HTML Report Formatter
"""

from __future__ import annotations

from pathlib import Path

from reporting.engine import ReportData

TEMPLATE_PATH = Path(__file__).parent.parent / "templates" / "report.html"


class HTMLFormatter:
    """Renders ReportData to styled HTML report."""

    @staticmethod
    def format_report(
        data: ReportData, custom_template: str | Path | None = None
    ) -> str:
        tpl_path = Path(custom_template) if custom_template else TEMPLATE_PATH
        if not tpl_path.exists():
            raise FileNotFoundError(f"Report template not found at {tpl_path}")

        try:
            from jinja2 import Template

            template_text = tpl_path.read_text(encoding="utf-8")
            template = Template(template_text)
            return template.render(data=data)
        except ImportError:
            # Fallback basic HTML if jinja2 is unexpectedly missing
            return f"<html><body><h1>{data.title}</h1><p>Case: {data.case_id}</p></body></html>"
