"""
Tests for RedBoot Core — Configuration Loader
"""

import pytest

from modules.core.config import RedBootConfig, ScopeConfig, SessionConfig


class TestScopeConfig:
    """Tests for ScopeConfig validation."""

    def test_scope_requires_targets(self):
        """Scope must have at least one authorized target."""
        with pytest.raises(ValueError, match="at least one authorized target"):
            ScopeConfig(targets=[])

    def test_scope_with_valid_targets(self):
        """Scope accepts valid target definitions."""
        scope = ScopeConfig(
            targets=["192.168.56.0/24"],
            description="Lab network",
        )
        assert scope.targets == ["192.168.56.0/24"]
        assert scope.description == "Lab network"

    def test_scope_with_exclusions(self):
        """Scope supports excluded addresses."""
        scope = ScopeConfig(
            targets=["192.168.56.0/24"],
            excluded=["192.168.56.1"],
        )
        assert "192.168.56.1" in scope.excluded


class TestSessionConfig:
    """Tests for SessionConfig defaults."""

    def test_default_values(self):
        """Session config has sensible defaults."""
        session = SessionConfig()
        assert session.operator == "lab-user"
        assert session.lab_name == "default-lab"

    def test_custom_values(self):
        """Session config accepts custom values."""
        session = SessionConfig(operator="student-01", lab_name="cyber-lab-1")
        assert session.operator == "student-01"
        assert session.lab_name == "cyber-lab-1"


class TestRedBootConfig:
    """Tests for the top-level configuration loader."""

    def test_from_dict_minimal(self):
        """Config can be created from a minimal dictionary."""
        data = {
            "scope": {
                "targets": ["192.168.56.0/24"],
            }
        }
        config = RedBootConfig.from_dict(data)
        assert config.scope.targets == ["192.168.56.0/24"]
        assert config.session.operator == "lab-user"

    def test_from_dict_full(self):
        """Config can be created from a complete dictionary."""
        data = {
            "session": {
                "operator": "student-01",
                "lab_name": "cyber-lab-1",
            },
            "scope": {
                "targets": ["192.168.56.0/24", "10.0.0.0/8"],
                "excluded": ["192.168.56.1"],
                "description": "Lab network",
            },
            "modules": {
                "reconnaissance": {"enabled": True},
                "forensics": {"enabled": False},
            },
        }
        config = RedBootConfig.from_dict(data)
        assert config.session.operator == "student-01"
        assert len(config.scope.targets) == 2
        assert config.is_module_enabled("reconnaissance") is True
        assert config.is_module_enabled("forensics") is False

    def test_is_module_enabled_missing_module(self):
        """Disabled by default for modules not in config."""
        data = {"scope": {"targets": ["127.0.0.1"]}}
        config = RedBootConfig.from_dict(data)
        assert config.is_module_enabled("nonexistent") is False

    def test_load_missing_file(self):
        """Loading a non-existent config file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            RedBootConfig.load("/nonexistent/config.yaml")
