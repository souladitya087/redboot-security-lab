"""
RedBoot Forensic Timeline Generator

Extracts MACB timestamps from filesystems and generates chronological event timelines.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from modules.core.logger import get_logger


class TimelineGenerator:
    """Generates chronological forensic activity timelines from directories or mounted images."""

    def __init__(self) -> None:
        self.logger = get_logger("forensic-timeline")

    @staticmethod
    def _format_time(timestamp: float | None) -> str:
        if timestamp is None or timestamp == 0:
            return "0000-00-00T00:00:00Z"
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()

    def generate_timeline(
        self,
        target_dir: str | Path,
        max_entries: int = 5000,
    ) -> list[dict[str, Any]]:
        """
        Recursively traverse target_dir and build MACB event timeline.
        """
        base = Path(target_dir)
        if not base.exists():
            raise FileNotFoundError(f"Directory not found: {base}")

        events: list[dict[str, Any]] = []

        for p in base.rglob("*"):
            if len(events) >= max_entries:
                break
            try:
                st = p.stat()
                rel_path = str(p.relative_to(base))

                # Modified (mtime)
                events.append(
                    {
                        "timestamp": self._format_time(st.st_mtime),
                        "epoch": st.st_mtime,
                        "event_type": "MODIFIED",
                        "path": rel_path,
                        "size": st.st_size,
                        "mode": oct(st.st_mode),
                    }
                )

                # Changed / Metadata (ctime)
                events.append(
                    {
                        "timestamp": self._format_time(st.st_ctime),
                        "epoch": st.st_ctime,
                        "event_type": "CHANGED_OR_METADATA",
                        "path": rel_path,
                        "size": st.st_size,
                        "mode": oct(st.st_mode),
                    }
                )

                # Accessed (atime)
                events.append(
                    {
                        "timestamp": self._format_time(st.st_atime),
                        "epoch": st.st_atime,
                        "event_type": "ACCESSED",
                        "path": rel_path,
                        "size": st.st_size,
                        "mode": oct(st.st_mode),
                    }
                )
            except (PermissionError, FileNotFoundError):
                continue

        # Sort chronologically
        events.sort(key=lambda x: x["epoch"], reverse=True)
        return events

    def export_csv(self, events: list[dict[str, Any]], output_path: str | Path) -> None:
        """Export timeline events to standard CSV file."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = ["timestamp", "epoch", "event_type", "path", "size", "mode"]

        with open(out, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for ev in events:
                writer.writerow(ev)
