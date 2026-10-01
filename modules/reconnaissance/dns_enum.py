"""
RedBoot DNS Enumeration Utility

Performs DNS record queries and reverse lookup within authorized scope.
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Any

from modules.core.logger import get_logger
from modules.core.scope import ScopeValidator

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]


class DNSEnumerator:
    """DNS Enumerator with scope enforcement."""

    def __init__(self, validator: ScopeValidator) -> None:
        self.validator = validator
        self.logger = get_logger("dns-enumerator")

    def reverse_lookup(self, ip: str) -> str | None:
        """Perform reverse DNS lookup for an IP address."""
        self.validator.validate(ip)
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except Exception:
            return None

    def resolve_domain(self, domain: str) -> dict[str, Any]:
        """
        Query basic DNS records for a domain name.
        """
        self.validator.validate(domain)
        timestamp = datetime.now(timezone.utc).isoformat()
        records: dict[str, list[str]] = {}

        # Resolve A records
        try:
            _, _, ips = socket.gethostbyname_ex(domain)
            records["A"] = ips
        except Exception:
            records["A"] = []

        # Optional dnspython resolution if available
        try:
            import dns.resolver  # type: ignore

            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            resolver.lifetime = 2.0

            for rtype in ["MX", "NS", "TXT", "CNAME", "AAAA"]:
                try:
                    answers = resolver.resolve(domain, rtype)
                    records[rtype] = [str(rdata) for rdata in answers]
                except Exception:
                    records[rtype] = []
        except ImportError:
            pass

        return {
            "module": "reconnaissance_dns",
            "timestamp": timestamp,
            "target": domain,
            "records": records,
        }
