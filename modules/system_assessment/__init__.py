"""
RedBoot System Assessment Module

System security posture, configuration audit, and privilege escalation analysis.
"""

from modules.system_assessment.auditor import (
    DANGEROUS_SUID_BINARIES,
    SENSITIVE_FILES,
    SystemAuditor,
)
from modules.system_assessment.compliance import ComplianceEvaluator

__all__ = [
    "SystemAuditor",
    "ComplianceEvaluator",
    "DANGEROUS_SUID_BINARIES",
    "SENSITIVE_FILES",
]
