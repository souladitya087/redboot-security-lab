"""
RedBoot Anti-Forensics & Volatile Memory Verification

Audits live system to ensure memory-only execution, absent swap persistence,
and non-persistence of investigative artifacts.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from modules.core.logger import get_logger


class AntiForensicsAuditor:
    """Verifies volatile execution guarantees and anti-forensic safeguards."""

    def __init__(self) -> None:
        self.logger = get_logger("anti-forensics")

    def check_swap_status(self) -> dict[str, Any]:
        """Verify that swap is completely disabled to avoid disk paging."""
        proc_swaps = Path("/proc/swaps")
        if not proc_swaps.exists():
            return {
                "swap_active": False,
                "status": "PASS",
                "details": "/proc/swaps not found (likely containerized or non-Linux).",
            }

        try:
            content = proc_swaps.read_text(encoding="utf-8").strip().splitlines()
            # If only the header line is present, swap is disabled
            swap_entries = [line for line in content[1:] if line.strip()]
            is_active = len(swap_entries) > 0

            return {
                "swap_active": is_active,
                "status": "FAIL" if is_active else "PASS",
                "active_devices": swap_entries,
                "recommendation": "Execute 'swapoff -a' to prevent disk leakage of sensitive operational memory.",
            }
        except Exception as e:
            return {"swap_active": False, "status": "UNKNOWN", "error": str(e)}

    def check_tmpfs_storage(
        self, check_paths: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """Verify designated directories reside on memory-backed tmpfs."""
        paths = check_paths or ["/tmp", "/var/log"]
        results: list[dict[str, Any]] = []

        for p in paths:
            target = Path(p)
            exists = target.exists()
            # On Linux, /proc/mounts can tell if filesystem is tmpfs
            is_tmpfs = False
            proc_mounts = Path("/proc/mounts")
            if proc_mounts.exists():
                try:
                    for line in proc_mounts.read_text().splitlines():
                        parts = line.split()
                        if len(parts) >= 3 and parts[1] == str(target):
                            is_tmpfs = parts[2] == "tmpfs"
                            break
                except Exception:
                    pass

            results.append(
                {
                    "path": str(target),
                    "exists": exists,
                    "is_tmpfs": is_tmpfs,
                    "status": "PASS" if is_tmpfs else "WARNING",
                }
            )
        return results

    def run_environment_audit(self) -> dict[str, Any]:
        """Run comprehensive volatile posture check."""
        timestamp = datetime.now(timezone.utc).isoformat()
        swap = self.check_swap_status()
        tmpfs = self.check_tmpfs_storage()

        return {
            "module": "anonymity_anti_forensics",
            "timestamp": timestamp,
            "swap_audit": swap,
            "memory_storage_audit": tmpfs,
            "posture": (
                "SECURE_VOLATILE" if not swap["swap_active"] else "PERSISTENCE_RISK"
            ),
        }
