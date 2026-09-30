# RedBoot Core Module
"""
Shared core utilities for all RedBoot modules.

Provides:
    - Configuration loading and validation
    - Structured logging
    - Scope validation (authorized target enforcement)
    - Session management
"""

from modules.core.config import RedBootConfig
from modules.core.logger import get_logger
from modules.core.scope import ScopeValidator

__all__ = ["RedBootConfig", "get_logger", "ScopeValidator"]
