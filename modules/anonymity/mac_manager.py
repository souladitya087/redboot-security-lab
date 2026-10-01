"""
RedBoot MAC Address Management

Generates valid, unicast, locally-administered MAC addresses and creates
safe commands for hardware address spoofing.
"""

from __future__ import annotations

import random
import re
from typing import Any

from modules.core.logger import get_logger


class MACManager:
    """Utility to generate, inspect, and manage MAC addresses."""

    def __init__(self) -> None:
        self.logger = get_logger("mac-manager")

    @staticmethod
    def generate_random_mac(vendor_prefix: str | None = None) -> str:
        """
        Generate a random valid MAC address.
        If no vendor prefix is supplied, sets the locally administered bit (bit 1 = 1)
        and unicast bit (bit 0 = 0) in the first byte (e.g. 02:xx:xx:xx:xx:xx).
        """
        if vendor_prefix:
            # Normalize prefix
            clean = vendor_prefix.replace("-", ":").replace(".", "")
            octets = clean.split(":")
            if len(octets) >= 3:
                first_three = [int(o, 16) for o in octets[:3]]
                remaining = [random.randint(0, 255) for _ in range(3)]
                return ":".join(f"{b:02x}" for b in (first_three + remaining))

        # First byte has bit 1 set (locally administered) and bit 0 clear (unicast)
        # 0x02, 0x06, 0x0A, 0x0E are valid
        first_byte = random.choice([0x02, 0x06, 0x0A, 0x0E])
        rest = [random.randint(0, 255) for _ in range(5)]
        return ":".join(f"{b:02x}" for b in [first_byte] + rest)

    @staticmethod
    def is_valid_mac(mac: str) -> bool:
        """Validate MAC address format."""
        pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
        return bool(re.match(pattern, mac))

    @staticmethod
    def generate_spoof_commands(interface: str, new_mac: str) -> list[str]:
        """
        Generate safe Linux iproute2 commands to change MAC address.
        """
        return [
            f"ip link set dev {interface} down",
            f"ip link set dev {interface} address {new_mac}",
            f"ip link set dev {interface} up",
        ]

    def create_spoof_plan(
        self, interface: str, target_mac: str | None = None
    ) -> dict[str, Any]:
        """Create a plan for MAC address alteration with auditing details."""
        mac = (
            target_mac
            if target_mac and self.is_valid_mac(target_mac)
            else self.generate_random_mac()
        )
        commands = self.generate_spoof_commands(interface, mac)
        return {
            "interface": interface,
            "target_mac": mac,
            "is_locally_administered": True,
            "execution_commands": commands,
        }
