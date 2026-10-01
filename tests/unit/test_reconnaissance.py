"""
Unit tests for Reconnaissance Module.
"""

from __future__ import annotations

import pytest

from modules.core.scope import ScopeValidator, ScopeViolation
from modules.reconnaissance.dns_enum import DNSEnumerator
from modules.reconnaissance.os_fingerprint import OSFingerprinter
from modules.reconnaissance.scanner import ReconScanner


class TestReconScanner:
    def test_scope_enforcement_raises_on_out_of_scope(self):
        validator = ScopeValidator(allowed_networks=["192.168.56.0/24"])
        scanner = ReconScanner(validator=validator)

        with pytest.raises(ScopeViolation):
            scanner.scan_host("10.0.0.1")

    def test_scan_host_in_scope_runs(self, monkeypatch):
        validator = ScopeValidator(allowed_networks=["192.168.56.0/24"])
        scanner = ReconScanner(validator=validator)

        # Mock check_port to avoid actual network traffic during unit test
        def mock_check_port(ip, port):
            if port == 22:
                return {
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ssh",
                    "banner": "SSH-2.0-OpenSSH",
                }
            return None

        monkeypatch.setattr(scanner, "check_port", mock_check_port)
        result = scanner.scan_host("192.168.56.10", ports=[22, 80])

        assert result["target"] == "192.168.56.10"
        assert result["status"] == "up"
        assert result["open_ports_count"] == 1
        assert result["findings"][0]["port"] == 22

    def test_scan_range_skips_out_of_scope(self, monkeypatch):
        validator = ScopeValidator(
            allowed_networks=["192.168.56.0/24"],
            excluded_addresses=["192.168.56.1"],
        )
        scanner = ReconScanner(validator=validator)

        def mock_scan_host(host, ports=None):
            return {
                "target": host,
                "ip": host,
                "status": "up",
                "ports_scanned": 1,
                "open_ports_count": 1,
                "findings": [
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "http",
                        "banner": "",
                    }
                ],
            }

        monkeypatch.setattr(scanner, "scan_host", mock_scan_host)
        # Scan a small /30 subnet (192.168.56.0/30 has .1, .2)
        results = scanner.scan_range("192.168.56.0/30", ports=[80])
        assert results["module"] == "reconnaissance"
        # .1 is excluded, so only .2 should be scanned
        scanned_hosts = [f["target"] for f in results["findings"]]
        assert "192.168.56.1" not in scanned_hosts


class TestOSFingerprinter:
    def test_ttl_linux_inference(self):
        validator = ScopeValidator(allowed_hosts=["localhost"])
        fingerprinter = OSFingerprinter(validator=validator)
        res = fingerprinter.guess_by_ttl(64)
        assert res["os_family"] == "Linux/Unix"
        assert res["estimated_hops"] == 0

    def test_ttl_windows_inference(self):
        validator = ScopeValidator(allowed_hosts=["localhost"])
        fingerprinter = OSFingerprinter(validator=validator)
        res = fingerprinter.guess_by_ttl(126)
        assert res["os_family"] == "Microsoft Windows"
        assert res["estimated_hops"] == 2

    def test_port_profile_windows(self):
        validator = ScopeValidator(allowed_hosts=["localhost"])
        fingerprinter = OSFingerprinter(validator=validator)
        res = fingerprinter.analyze_ports([135, 445, 3389])
        assert res["os_family"] == "Microsoft Windows"
        assert res["confidence"] >= 0.8

    def test_port_profile_linux(self):
        validator = ScopeValidator(allowed_hosts=["localhost"])
        fingerprinter = OSFingerprinter(validator=validator)
        res = fingerprinter.analyze_ports([22, 80])
        assert res["os_family"] == "Linux/POSIX"


class TestDNSEnumerator:
    def test_scope_enforced(self):
        validator = ScopeValidator(allowed_hosts=["allowed.lab"])
        dns_enum = DNSEnumerator(validator=validator)
        with pytest.raises(ScopeViolation):
            dns_enum.resolve_domain("unauthorized.com")
