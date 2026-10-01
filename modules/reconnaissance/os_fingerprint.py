"""
RedBoot OS Fingerprinting

Infers the target operating system family using TTL analysis and port signatures.
"""

from __future__ import annotations

from typing import Any

from modules.core.logger import get_logger
from modules.core.scope import ScopeValidator


class OSFingerprinter:
    """Heuristic OS fingerprinter based on TTL and active service signatures."""

    def __init__(self, validator: ScopeValidator) -> None:
        self.validator = validator
        self.logger = get_logger("os-fingerprint")

    def guess_by_ttl(self, ttl: int) -> dict[str, Any]:
        """
        Estimate OS family based on typical default IP TTL values:
        - Linux/Unix: ~64
        - Windows: ~128
        - Solaris/Cisco/Network Appliances: ~255
        """
        if ttl <= 64:
            return {
                "os_family": "Linux/Unix",
                "estimated_hops": 64 - ttl,
                "confidence": 0.75,
                "details": "Initial TTL estimated at 64 (standard for Linux/macOS/BSD kernels)",
            }
        elif ttl <= 128:
            return {
                "os_family": "Microsoft Windows",
                "estimated_hops": 128 - ttl,
                "confidence": 0.80,
                "details": "Initial TTL estimated at 128 (standard for Windows NT/10/11/Server)",
            }
        else:
            return {
                "os_family": "Network Appliance / Solaris",
                "estimated_hops": 255 - ttl,
                "confidence": 0.70,
                "details": "Initial TTL estimated at 255 (standard for Cisco IOS or Solaris)",
            }

    def analyze_ports(self, open_ports: list[int]) -> dict[str, Any]:
        """Infer OS profile based on open port patterns."""
        port_set = set(open_ports)
        if {135, 139, 445}.intersection(port_set) or 3389 in port_set:
            return {
                "os_family": "Microsoft Windows",
                "confidence": 0.90,
                "indicators": ["MSRPC (135)", "SMB (445)", "RDP (3389)"],
            }
        if 22 in port_set and not {135, 445}.intersection(port_set):
            return {
                "os_family": "Linux/POSIX",
                "confidence": 0.80,
                "indicators": ["SSH (22) without Windows RPC/SMB"],
            }
        return {
            "os_family": "Unknown",
            "confidence": 0.20,
            "indicators": [],
        }
