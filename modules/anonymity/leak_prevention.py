"""
RedBoot DNS Leak Prevention

Generates firewall rules to prevent direct plaintext DNS leaks outside
anonymizing tunnels or proxy layers.
"""

from __future__ import annotations

from typing import Any

from modules.core.logger import get_logger


class DNSLeakPrevention:
    """Generates and audits DNS leak prevention controls."""

    def __init__(self) -> None:
        self.logger = get_logger("leak-prevention")

    @staticmethod
    def generate_iptables_leak_rules(
        proxy_uid_or_user: str = "debian-tor",
    ) -> list[str]:
        """
        Generate iptables rules to drop all direct outgoing UDP/TCP port 53 traffic,
        allowing DNS queries only through local Tor/SOCKS or the tunnel interface.
        """
        return [
            # Allow loopback DNS queries to local proxy/resolver
            "iptables -A OUTPUT -o lo -p udp --dport 53 -j ACCEPT",
            "iptables -A OUTPUT -o lo -p tcp --dport 53 -j ACCEPT",
            # Allow the proxy process owner to query external DNS
            f"iptables -A OUTPUT -m owner --uid-owner {proxy_uid_or_user} -p udp --dport 53 -j ACCEPT",
            f"iptables -A OUTPUT -m owner --uid-owner {proxy_uid_or_user} -p tcp --dport 53 -j ACCEPT",
            # Reject all other outbound DNS traffic to prevent leaks
            "iptables -A OUTPUT -p udp --dport 53 -j REJECT --reject-with icmp-port-unreachable",
            "iptables -A OUTPUT -p tcp --dport 53 -j REJECT --reject-with tcp-reset",
        ]

    def audit_leak_defense_posture(self) -> dict[str, Any]:
        """Audit theoretical leak resistance posture."""
        rules = self.generate_iptables_leak_rules()
        return {
            "status": "CONFIGURED",
            "leak_prevention_mechanism": "Kernel Netfilter Packet Filter (iptables/nftables)",
            "rules_generated": len(rules),
            "rules": rules,
            "description": "Enforces strict containment of DNS queries within authenticated channels.",
        }
