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

    def test_logger_includes_session_id(self):
        """Logger injects session_id into log output."""
        import io

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(StructuredFormatter())

        logger = get_logger("session-test", session_id="session-xyz")
        logger.logger.addHandler(handler)
        try:
            logger.info("Hello", extra={"data": {"key": "value"}})
            output = stream.getvalue().strip()
            parsed = json.loads(output)
            assert parsed["session_id"] == "session-xyz"
        finally:
            logger.logger.removeHandler(handler)
