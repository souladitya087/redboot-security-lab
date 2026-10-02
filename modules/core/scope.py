"""
RedBoot Scope Validator

Enforces that all assessment operations stay within the authorized target scope.
This is a critical safety control — modules MUST validate targets through this
validator before performing any active operations.

Supports:
    - IPv4 addresses and CIDR ranges
    - Hostname allow-lists
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from modules.core.logger import get_logger


@dataclass
class ScopeValidator:
    """
    Validates targets against an authorized scope definition.

    All assessment modules must call `validate()` before scanning,
    probing, or interacting with any target. Operations against
    out-of-scope targets are refused.

    Example:
        validator = ScopeValidator(
            allowed_networks=["192.168.56.0/24"],
            allowed_hosts=["target.lab.local"],
            excluded_addresses=["192.168.56.1"],
        )
        validator.validate("192.168.56.10")   # True
        validator.validate("10.0.0.1")         # raises ScopeViolation
    """

    allowed_networks: list[str] = field(default_factory=list)
    allowed_hosts: list[str] = field(default_factory=list)
    excluded_addresses: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._logger = get_logger("scope-validator")

        # Parse CIDR networks
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for net_str in self.allowed_networks:
            try:
                self._networks.append(ipaddress.ip_network(net_str, strict=False))
            except ValueError as e:
                raise ValueError(f"Invalid network in scope: {net_str}") from e

        # Parse excluded addresses
        self._excluded: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        for addr_str in self.excluded_addresses:
            try:
                self._excluded.add(ipaddress.ip_address(addr_str))
            except ValueError as e:
                raise ValueError(f"Invalid excluded address: {addr_str}") from e

        # Normalize allowed hosts to lowercase
        self._hosts: set[str] = {h.lower() for h in self.allowed_hosts}

    def validate(self, target: str) -> bool:
        """
        Check if a target is within the authorized scope.

        Args:
            target: An IP address or hostname to validate.

        Returns:
            True if the target is in scope.

        Raises:
            ScopeViolation: If the target is out of scope or explicitly excluded.
        """
        # Try as IP address first
        try:
            addr = ipaddress.ip_address(target)

            # Check exclusions
            if addr in self._excluded:
                self._logger.warning(
                    f"SCOPE VIOLATION: {target} is explicitly excluded",
                    extra={"data": {"target": target, "reason": "excluded"}},
                )
                raise ScopeViolation(target, "Target is explicitly excluded from scope")

            # Check allowed networks
            for network in self._networks:
                if addr in network:
                    self._logger.info(
                        f"Scope validated: {target} is in {network}",
                        extra={"data": {"target": target, "network": str(network)}},
                    )
                    return True

            # Check if IP was specified directly in allowed_hosts
            if str(addr) in self._hosts:
                self._logger.info(
                    f"Scope validated: host {target} is allowed",
                    extra={"data": {"target": target}},
                )
                return True

            self._logger.warning(
                f"SCOPE VIOLATION: {target} is not in any authorized network",
                extra={"data": {"target": target, "reason": "not_in_scope"}},
            )
            raise ScopeViolation(target, "Target is not in any authorized network")

        except ValueError:
            # Not an IP — treat as hostname
            if target.lower() in self._hosts:
                self._logger.info(
                    f"Scope validated: hostname {target} is allowed",
                    extra={"data": {"target": target}},
                )
                return True

            self._logger.warning(
                f"SCOPE VIOLATION: hostname {target} is not in allowed hosts",
                extra={"data": {"target": target, "reason": "hostname_not_allowed"}},
            )
            raise ScopeViolation(target, "Hostname is not in the allowed hosts list")

    def is_in_scope(self, target: str) -> bool:
        """
        Non-raising version of validate(). Returns False instead of raising.

        Args:
            target: An IP address or hostname to check.

        Returns:
            True if in scope, False otherwise.
        """
        try:
            return self.validate(target)
        except ScopeViolation:
            return False

    @classmethod
    def from_config(cls, scope_config) -> "ScopeValidator":
        """
        Create a ScopeValidator from a ScopeConfig dataclass.

        Args:
            scope_config: A ScopeConfig instance from the configuration loader.

        Returns:
            A configured ScopeValidator.
        """
        networks = []
        hosts = []

        for target in scope_config.targets:
            try:
                ipaddress.ip_network(target, strict=False)
                networks.append(target)
            except ValueError:
                # Treat as hostname
                hosts.append(target)

        return cls(
            allowed_networks=networks,
            allowed_hosts=hosts,
            excluded_addresses=scope_config.excluded,
        )


class ScopeViolation(Exception):
    """
    Raised when an operation targets a system outside the authorized scope.

    This is a critical safety exception. Modules must not catch and ignore this.
    """

    def __init__(self, target: str, reason: str) -> None:
        self.target = target
        self.reason = reason
        super().__init__(
            f"SCOPE VIOLATION — Target '{target}' is out of scope: {reason}. "
            f"RedBoot refuses to operate on unauthorized targets."
        )
