"""
RedBoot Configuration Loader

Loads and validates YAML-based configuration for all RedBoot modules.
Provides a single source of truth for session settings, scope definitions,
and module-specific parameters.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


# Default configuration file path
DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "redboot.yaml"


@dataclass
class ScopeConfig:
    """Defines the authorized assessment scope."""

    targets: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    description: str = ""

    def __post_init__(self) -> None:
        if not self.targets:
            raise ValueError(
                "Scope must define at least one authorized target. "
                "RedBoot refuses to operate without an explicit scope."
            )


@dataclass
class SessionConfig:
    """Session-level metadata."""

    operator: str = "lab-user"
    session_id: str = ""
    lab_name: str = "default-lab"
    output_dir: str = "output"


@dataclass
class RedBootConfig:
    """
    Top-level RedBoot configuration.

    Loads from a YAML file and provides typed access to all settings.

    Example YAML:
        session:
          operator: "student-01"
          lab_name: "cyber-lab-1"
        scope:
          targets:
            - "192.168.56.0/24"
          excluded:
            - "192.168.56.1"
          description: "Isolated VirtualBox lab network"
        modules:
          reconnaissance:
            enabled: true
    """

    session: SessionConfig = field(default_factory=SessionConfig)
    scope: ScopeConfig = field(default_factory=lambda: ScopeConfig(targets=["127.0.0.1"]))
    modules: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> "RedBootConfig":
        """
        Load configuration from a YAML file.

        Args:
            config_path: Path to the YAML configuration file.
                         Falls back to DEFAULT_CONFIG_PATH, then env var
                         REDBOOT_CONFIG.

        Returns:
            A validated RedBootConfig instance.

        Raises:
            FileNotFoundError: If the config file does not exist.
            ValueError: If required fields are missing or invalid.
        """
        if config_path is None:
            config_path = os.environ.get("REDBOOT_CONFIG", str(DEFAULT_CONFIG_PATH))

        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(
                f"Configuration file not found: {path}\n"
                f"Create a config file or set REDBOOT_CONFIG env var."
            )

        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

        return cls._from_dict(raw)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RedBootConfig":
        """Create a config from a dictionary (useful for testing)."""
        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> "RedBootConfig":
        """Internal: parse a raw dict into a typed config."""
        session_data = data.get("session", {})
        scope_data = data.get("scope", {})
        modules_data = data.get("modules", {})

        session = SessionConfig(**session_data)
        scope = ScopeConfig(**scope_data)

        return cls(session=session, scope=scope, modules=modules_data)

    def is_module_enabled(self, module_name: str) -> bool:
        """Check if a module is enabled in the configuration."""
        module_cfg = self.modules.get(module_name, {})
        return module_cfg.get("enabled", False)
