"""
RedBoot Structured Logger

Provides consistent, structured JSON logging across all modules.
Every log entry includes timestamp, module name, session ID, and severity
to support audit trail requirements.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any


class StructuredFormatter(logging.Formatter):
    """
    Formats log records as structured JSON lines.

    Output format:
        {"timestamp": "...", "level": "INFO", "module": "recon", "message": "...", "data": {...}}
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
        }

        # Include extra structured data if provided
        if hasattr(record, "data") and record.data:  # type: ignore[attr-defined]
            log_entry["data"] = record.data  # type: ignore[attr-defined]

        # Include session_id if available
        if hasattr(record, "session_id") and record.session_id:  # type: ignore[attr-defined]
            log_entry["session_id"] = record.session_id  # type: ignore[attr-defined]

        return json.dumps(log_entry, default=str)


class RedBootLogger(logging.LoggerAdapter):
    """
    Logger adapter that injects session context into every log message.

    Usage:
        logger = get_logger("reconnaissance", session_id="abc-123")
        logger.info("Scan started", extra={"data": {"target": "192.168.56.0/24"}})
    """

    def process(
        self, msg: str, kwargs: dict[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        extra = kwargs.get("extra", {})
        extra["session_id"] = self.extra.get("session_id", "")
        kwargs["extra"] = extra
        return msg, kwargs


def get_logger(
    module_name: str,
    session_id: str = "",
    level: int = logging.INFO,
) -> RedBootLogger:
    """
    Create a structured logger for a RedBoot module.

    Args:
        module_name: Name of the module (e.g., "reconnaissance", "forensics").
        session_id: Current session identifier for audit correlation.
        level: Logging level (default: INFO).

    Returns:
        A configured RedBootLogger instance.
    """
    logger = logging.getLogger(f"redboot.{module_name}")
    logger.setLevel(level)

    # Avoid adding duplicate handlers
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(StructuredFormatter())
        logger.addHandler(handler)

    return RedBootLogger(logger, {"session_id": session_id})
