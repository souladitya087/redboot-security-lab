"""
Tests for RedBoot Core — Structured Logger
"""

import json
import logging

from modules.core.logger import get_logger, StructuredFormatter


class TestStructuredFormatter:
    """Tests for JSON log formatting."""

    def test_format_produces_valid_json(self):
        """Log output is valid JSON."""
        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="redboot.test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["level"] == "INFO"
        assert parsed["module"] == "redboot.test"
        assert parsed["message"] == "Test message"
        assert "timestamp" in parsed


class TestGetLogger:
    """Tests for logger factory."""

    def test_returns_logger_with_module_name(self):
        """Logger is named with the redboot prefix."""
        logger = get_logger("test-module")
        assert logger.logger.name == "redboot.test-module"

    def test_logger_includes_session_id(self, capfd):
        """Logger injects session_id into log output."""
        logger = get_logger("test-module", session_id="session-xyz")
        logger.info("Hello", extra={"data": {"key": "value"}})
        captured = capfd.readouterr()
        parsed = json.loads(captured.out.strip())
        assert parsed["session_id"] == "session-xyz"
