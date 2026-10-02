"""
Integration tests for the RedBoot automated scenario execution pipeline.

Tests end-to-end execution of multi-stage lab scenarios, evidence vaulting,
tamper-evident chain of custody, and multi-format report generation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from modules.core.scope import ScopeViolation
from modules.evidence.verifier import EvidenceVerifier
from redboot import cli as redboot_cli
from scripts.run_scenario import ScenarioRunner


class TestScenarioPipelineIntegration:
    """Integration test suite for the complete RedBoot assessment pipeline."""

    @pytest.fixture
    def mock_scenario_path(self, tmp_path: Path) -> Path:
        """Create a complete, fully scoped multi-stage scenario definition."""
        scenario_data = {
            "scenario": {
                "id": "SCN-TEST-001",
                "name": "Integration Test Pipeline",
                "description": "Automated end-to-end testing of assessment modules.",
                "version": "1.0.0",
            },
            "session": {
                "operator": "test-runner",
                "lab_name": "Integration Test Environment",
                "case_id": "CASE-INT-2026",
            },
            "scope": {
                "targets": ["127.0.0.1"],
                "excluded": [],
                "description": "Localhost testing loopback",
            },
            "stages": [
                {
                    "stage": "reconnaissance",
                    "enabled": True,
                    "parameters": {"ports": [9], "timeout": 0.05},
                },
                {
                    "stage": "vulnerability_assessment",
                    "enabled": True,
                    "parameters": {},
                },
                {
                    "stage": "system_assessment",
                    "enabled": True,
                    "parameters": {
                        "target_root": str(tmp_path),
                        "check_compliance": True,
                    },
                },
                {
                    "stage": "anonymity",
                    "enabled": True,
                    "parameters": {},
                },
                {
                    "stage": "forensics",
                    "enabled": True,
                    "parameters": {"timeline_target": str(tmp_path)},
                },
            ],
            "evidence": {
                "auto_collect": True,
                "description": "Integration test stage outputs",
            },
            "reporting": {
                "enabled": True,
                "formats": ["html", "markdown", "json"],
            },
        }

        scenario_file = tmp_path / "test_scenario.yaml"
        scenario_file.write_text(yaml.safe_dump(scenario_data), encoding="utf-8")
        return scenario_file

    def test_scenario_dry_run(self, mock_scenario_path: Path, tmp_path: Path) -> None:
        """Dry-run validates scope and syntax without executing stages."""
        out_dir = tmp_path / "dry_run_out"
        runner = ScenarioRunner(scenario_path=mock_scenario_path, output_dir=out_dir)

        results = runner.execute_all(dry_run=True)
        assert results["scenario_id"] == "SCN-TEST-001"
        assert len(results["stages_executed"]) == 0
        assert len(results["artifacts_collected"]) == 0

    def test_scenario_full_end_to_end_pipeline(
        self, mock_scenario_path: Path, tmp_path: Path
    ) -> None:
        """Full end-to-end execution of all stages, vaulting, and reports."""
        out_dir = tmp_path / "full_pipeline_out"
        runner = ScenarioRunner(scenario_path=mock_scenario_path, output_dir=out_dir)

        results = runner.execute_all(dry_run=False)

        # 1. Assert all 5 stages ran
        expected_stages = [
            "reconnaissance",
            "vulnerability_assessment",
            "system_assessment",
            "anonymity",
            "forensics",
        ]
        assert results["stages_executed"] == expected_stages

        # 2. Assert raw stage artifacts were generated
        assert (out_dir / "recon.json").exists()
        assert (out_dir / "vuln.json").exists()
        assert (out_dir / "system.json").exists()
        assert (out_dir / "anonymity.json").exists()
        assert (out_dir / "forensics.json").exists()
        assert (out_dir / "timeline.csv").exists()

        # 3. Assert reports were generated in all 3 formats
        assert (out_dir / "report.html").exists()
        assert (out_dir / "report.md").exists()
        assert (out_dir / "report.json").exists()

        # 4. Assert multi-format reports contain expected data
        report_data = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
        assert report_data["case_id"] == "CASE-INT-2026"
        assert report_data["operator"] == "test-runner"
        assert "## 1. Executive Summary" in (out_dir / "report.md").read_text(
            encoding="utf-8"
        )
        assert "## 4. Digital Evidence" in (out_dir / "report.md").read_text(
            encoding="utf-8"
        )
        assert "<!DOCTYPE html>" in (out_dir / "report.html").read_text(
            encoding="utf-8"
        )

        # 5. Assert evidence vaulting and cryptographic chain of custody
        vault_dir = out_dir / "evidence_vault"
        assert vault_dir.exists()
        assert len(results["artifacts_collected"]) >= 5

        verifier = EvidenceVerifier(vault_dir=vault_dir)
        verification_report = verifier.verify_vault()
        assert verification_report["overall_integrity_verified"] is True
        assert verification_report["chain_of_custody_status"] == "VALID"
        assert verification_report["all_file_hashes_match"] is True

    def test_scope_enforcement_aborts_out_of_scope_target(self, tmp_path: Path) -> None:
        """Scope violation aborts execution before active network probes."""
        forbidden_scenario = {
            "scenario": {"id": "SCN-FORBIDDEN", "name": "Illegal Target"},
            "session": {"operator": "unauthorized", "case_id": "CASE-BAD"},
            "scope": {
                "targets": ["127.0.0.1"],
                "excluded": [],
            },
            "stages": [
                {
                    "stage": "reconnaissance",
                    "enabled": True,
                    "parameters": {"ports": [80], "timeout": 0.05},
                }
            ],
        }

        # Deliberately modify stage target to an unauthorized address
        scenario_file = tmp_path / "bad_scenario.yaml"
        forbidden_scenario["scope"]["targets"] = ["8.8.8.8"]  # Public IP outside lab
        scenario_file.write_text(yaml.safe_dump(forbidden_scenario), encoding="utf-8")

        runner = ScenarioRunner(
            scenario_path=scenario_file, output_dir=tmp_path / "out"
        )
        # Ensure that attempting to scan an out-of-scope host fails ScopeValidator check
        with pytest.raises(ScopeViolation):
            runner.validator.validate("198.51.100.1")

    def test_cli_redboot_status(self) -> None:
        """Test top-level CLI status invocation."""
        runner = CliRunner()
        res = runner.invoke(redboot_cli, ["status"])
        assert res.exit_code == 0
        assert "RedBoot" in res.output
        assert "ONLINE" in res.output

    def test_cli_redboot_scenario_dry_run(
        self, mock_scenario_path: Path, tmp_path: Path
    ) -> None:
        """Test unified redboot CLI invoking scenario in dry-run mode."""
        runner = CliRunner()
        res = runner.invoke(
            redboot_cli,
            [
                "scenario",
                "--scenario",
                str(mock_scenario_path),
                "--output-dir",
                str(tmp_path / "cli_out"),
                "--dry-run",
            ],
        )
        assert res.exit_code == 0
        assert "SCN-TEST-001" in res.output
        assert "dry-run" in res.output
