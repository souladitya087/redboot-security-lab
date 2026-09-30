"""
Tests for RedBoot Core — Scope Validator
"""

import pytest

from modules.core.scope import ScopeValidator, ScopeViolation


class TestScopeValidator:
    """Tests for scope enforcement."""

    @pytest.fixture
    def validator(self):
        """Standard lab scope validator."""
        return ScopeValidator(
            allowed_networks=["192.168.56.0/24"],
            allowed_hosts=["target.lab.local"],
            excluded_addresses=["192.168.56.1"],
        )

    def test_valid_ip_in_scope(self, validator):
        """IP within allowed network is accepted."""
        assert validator.validate("192.168.56.10") is True

    def test_ip_out_of_scope_raises(self, validator):
        """IP outside allowed network raises ScopeViolation."""
        with pytest.raises(ScopeViolation, match="not in any authorized network"):
            validator.validate("10.0.0.1")

    def test_excluded_ip_raises(self, validator):
        """Explicitly excluded IP raises ScopeViolation."""
        with pytest.raises(ScopeViolation, match="explicitly excluded"):
            validator.validate("192.168.56.1")

    def test_valid_hostname(self, validator):
        """Allowed hostname is accepted."""
        assert validator.validate("target.lab.local") is True

    def test_hostname_case_insensitive(self, validator):
        """Hostname matching is case-insensitive."""
        assert validator.validate("TARGET.LAB.LOCAL") is True

    def test_unknown_hostname_raises(self, validator):
        """Unknown hostname raises ScopeViolation."""
        with pytest.raises(ScopeViolation, match="not in the allowed hosts"):
            validator.validate("evil.external.com")

    def test_is_in_scope_returns_bool(self, validator):
        """Non-raising method returns boolean."""
        assert validator.is_in_scope("192.168.56.10") is True
        assert validator.is_in_scope("10.0.0.1") is False
        assert validator.is_in_scope("192.168.56.1") is False

    def test_invalid_network_raises_valueerror(self):
        """Invalid CIDR network in config raises ValueError."""
        with pytest.raises(ValueError, match="Invalid network"):
            ScopeValidator(allowed_networks=["not-a-network"])

    def test_invalid_excluded_raises_valueerror(self):
        """Invalid excluded address raises ValueError."""
        with pytest.raises(ValueError, match="Invalid excluded address"):
            ScopeValidator(
                allowed_networks=["192.168.56.0/24"],
                excluded_addresses=["not-an-ip"],
            )

    def test_multiple_networks(self):
        """Validator supports multiple authorized networks."""
        validator = ScopeValidator(
            allowed_networks=["192.168.56.0/24", "10.10.0.0/16"],
        )
        assert validator.is_in_scope("192.168.56.100") is True
        assert validator.is_in_scope("10.10.5.5") is True
        assert validator.is_in_scope("172.16.0.1") is False

    def test_empty_scope_allows_nothing(self):
        """Validator with no networks or hosts allows nothing."""
        validator = ScopeValidator()
        assert validator.is_in_scope("192.168.56.10") is False
        assert validator.is_in_scope("anything.com") is False
