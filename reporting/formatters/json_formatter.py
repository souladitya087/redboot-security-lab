"""
RedBoot JSON Report Formatter
"""

from __future__ import annotations

import json
from dataclasses import asdict

from reporting.engine import ReportData


class JSONFormatter:
    """Formats ReportData into standard JSON structure."""

    @staticmethod
    def format_report(data: ReportData, indent: int = 2) -> str:
        data_dict = asdict(data)
        return json.dumps(data_dict, indent=indent)
