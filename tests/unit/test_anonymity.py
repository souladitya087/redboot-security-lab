"""
Unit tests for Anonymity / Non-Traceability Module.
"""

from __future__ import annotations

from modules.anonymity.anti_forensics import AntiForensicsAuditor
from modules.anonymity.leak_prevention import DNSLeakPrevention
from modules.anonymity.mac_manager import MACManager
from modules.anonymity.proxy_manager import ProxyManager


class TestMACManager:
    def test_generate_random_mac(self):
        mac = MACManager.generate_random_mac()
        assert MACManager.is_valid_mac(mac)
        first_byte = int(mac.split(":")[0], 16)
        # Verify locally administered bit (bit 1 is set)
        assert (first_byte & 0x02) == 0x02
        # Verify unicast bit (bit 0 is clear)
        assert (first_byte & 0x01) == 0x00

    def test_generate_spoof_commands(self):
        cmds = MACManager.generate_spoof_commands("eth0", "02:11:22:33:44:55")
        assert len(cmds) == 3
        assert "ip link set dev eth0 down" in cmds[0]
        assert "02:11:22:33:44:55" in cmds[1]


class TestDNSLeakPrevention:
    def test_generate_iptables_leak_rules(self):
        rules = DNSLeakPrevention.generate_iptables_leak_rules()
        assert len(rules) >= 4
        # Verify drop/reject of unauthenticated DNS
        assert any("REJECT" in r and "53" in r for r in rules)


class TestProxyManager:
    def test_proxy_configuration_schema(self):
        pm = ProxyManager(proxy_host="127.0.0.1", proxy_port=9050)
        config = pm.get_proxy_configuration()
        assert config["proxy_type"] == "socks5h"
        assert config["port"] == 9050
        assert "ALL_PROXY" in config["env_vars"]


class TestAntiForensicsAuditor:
    def test_check_swap_status_schema(self):
        auditor = AntiForensicsAuditor()
        swap = auditor.check_swap_status()
        assert "swap_active" in swap
        assert "status" in swap
