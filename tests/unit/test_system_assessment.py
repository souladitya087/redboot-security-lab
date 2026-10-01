"""
Unit tests for System Assessment Module.
"""

from __future__ import annotations

import stat
from pathlib import Path
from unittest.mock import MagicMock

from modules.system_assessment.auditor import SystemAuditor
from modules.system_assessment.compliance import ComplianceEvaluator


class TestSystemAuditor:
    def test_audit_accounts_uid_zero_detection(self, tmp_path: Path):
        etc = tmp_path / "etc"
        etc.mkdir()
        passwd = etc / "passwd"
        passwd.write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "backdoor:x:0:0:evil:/home/backdoor:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
            encoding="utf-8",
        )

        auditor = SystemAuditor(root_dir=tmp_path)
        res = auditor.audit_accounts()

        assert res["total_users"] == 3
        assert "root" in res["uid_zero_accounts"]
        assert "backdoor" in res["uid_zero_accounts"]
        assert len(res["findings"]) >= 1
        assert res["findings"][0]["severity"] == "CRITICAL"

    def test_audit_sensitive_files(self, tmp_path: Path, monkeypatch):
        etc = tmp_path / "etc"
        etc.mkdir(exist_ok=True)
        shadow = etc / "shadow"
        shadow.write_text("root:$6$...:19000:0:99999:7:::\n", encoding="utf-8")

        # Mock stat to reflect Unix world-readable permissions (0o644) cross-platform
        original_stat = Path.stat

        def mock_stat(self_path):
            st = original_stat(self_path)
            if self_path.name == "shadow":
                mock = MagicMock(wraps=st)
                mock.st_mode = stat.S_IFREG | 0o644
                return mock
            return st

        monkeypatch.setattr(Path, "stat", mock_stat)

        auditor = SystemAuditor(root_dir=tmp_path)
        findings = auditor.audit_sensitive_files()
        shadow_finding = next((f for f in findings if f["file"] == "/etc/shadow"), None)

        assert shadow_finding is not None
        assert shadow_finding["world_readable"] is True
        assert shadow_finding["severity"] == "CRITICAL"

    def test_audit_suid_binaries(self, tmp_path: Path, monkeypatch):
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        fake_find = bin_dir / "find"
        fake_find.write_text("#!/bin/sh\n", encoding="utf-8")

        # Mock stat to reflect SUID bit (0o104755) cross-platform
        original_stat = Path.stat

        def mock_stat(self_path):
            st = original_stat(self_path)
            if self_path.name == "find":
                mock = MagicMock(wraps=st)
                mock.st_mode = stat.S_IFREG | stat.S_ISUID | 0o755
                return mock
            return st

        monkeypatch.setattr(Path, "stat", mock_stat)

        auditor = SystemAuditor(root_dir=tmp_path)
        findings = auditor.audit_suid_binaries(search_paths=["/bin"])

        find_entry = next((f for f in findings if f["name"] == "find"), None)
        assert find_entry is not None
        assert find_entry["is_suid"] is True
        assert find_entry["is_known_gtfobin"] is True
        assert find_entry["severity"] == "HIGH"


class TestComplianceEvaluator:
    def test_compliance_scoring_fails_with_critical_issues(self):
        mock_audit = {
            "findings": {
                "accounts": {"uid_zero_accounts": ["root", "hacker"]},
                "file_security": [{"file": "/etc/shadow", "world_readable": True}],
                "suid_binaries": [{"name": "nmap", "is_known_gtfobin": True}],
            }
        }
        res = ComplianceEvaluator.evaluate(mock_audit)
        assert res["score"] < 50
        assert res["rating"] == "CRITICAL_RISK"
        assert res["checks_passed"] <= 1
