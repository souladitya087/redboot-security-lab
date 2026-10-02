"""
RedBoot Scenario Runner

Executes scripted, reproducible security assessment and forensic scenarios.
Enforces scope validation, collects evidence into the tamper-evident vault,
and triggers multi-format report generation.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click
import yaml

from modules.anonymity.anti_forensics import AntiForensicsAuditor
from modules.anonymity.leak_prevention import DNSLeakPrevention
from modules.core.logger import get_logger
from modules.core.scope import ScopeValidator, ScopeViolation
from modules.evidence.collector import EvidenceCollector
from modules.forensics.timeline import TimelineGenerator
from modules.reconnaissance.scanner import ReconScanner
from modules.system_assessment.auditor import SystemAuditor
from modules.system_assessment.compliance import ComplianceEvaluator
from modules.vulnerability_assessment.vuln_scanner import VulnerabilityScanner
from reporting.engine import ReportEngine
from reporting.formatters.html_formatter import HTMLFormatter
from reporting.formatters.json_formatter import JSONFormatter
from reporting.formatters.markdown_formatter import MarkdownFormatter


class ScenarioExecutionError(Exception):
    """Raised when an unrecoverable scenario execution error occurs."""


class ScenarioRunner:
    """Orchestrates scenario execution through RedBoot modules."""

    def __init__(
        self, scenario_path: str | Path, output_dir: str | Path | None = None
    ) -> None:
        self.scenario_path = Path(scenario_path)
        if not self.scenario_path.exists():
            raise FileNotFoundError(
                f"Scenario definition not found: {self.scenario_path}"
            )

        with open(self.scenario_path, "r", encoding="utf-8") as f:
            self.data: dict[str, Any] = yaml.safe_load(f) or {}

        scenario_meta = self.data.get("scenario", {})
        session_meta = self.data.get("session", {})

        self.scenario_id = scenario_meta.get("id", "SCN-DEFAULT")
        self.scenario_name = scenario_meta.get("name", "Lab Scenario")
        self.case_id = session_meta.get("case_id", "CASE-DEFAULT")
        self.operator = session_meta.get("operator", "operator")
        self.lab_name = session_meta.get("lab_name", "RedBoot Lab")

        # Setup output directory
        base_output = output_dir or Path("output") / self.scenario_id.lower()
        self.output_dir = Path(base_output)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.vault_dir = self.output_dir / "evidence_vault"

        self.logger = get_logger("scenario-runner")

        # Configure scope validator
        scope_data = self.data.get("scope", {})
        targets = scope_data.get("targets", ["127.0.0.1"])
        excluded = scope_data.get("excluded", [])
        self.validator = ScopeValidator(
            allowed_networks=[t for t in targets if "/" in t],
            allowed_hosts=[t for t in targets if "/" not in t],
            excluded_addresses=excluded,
        )

        self.collector = EvidenceCollector(vault_dir=self.vault_dir)
        self.results: dict[str, Any] = {
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "case_id": self.case_id,
            "operator": self.operator,
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "stages_executed": [],
            "artifacts_collected": [],
        }

    def execute_all(self, dry_run: bool = False) -> dict[str, Any]:
        """Execute all defined scenario stages sequentially."""
        self.logger.info(
            f"Starting scenario execution: {self.scenario_name} ({self.scenario_id})"
        )
        if dry_run:
            self.logger.info(
                "[DRY RUN] Scope and parameters validated. Skipping active execution."
            )
            return self.results

        stages = self.data.get("stages", [])
        recon_data: dict[str, Any] | None = None

        for stage_cfg in stages:
            stage_name = stage_cfg.get("stage", "")
            if not stage_cfg.get("enabled", True):
                continue

            self.logger.info(f"Executing stage: {stage_name}")
            params = stage_cfg.get("parameters", {})

            if stage_name == "reconnaissance":
                recon_data = self._run_reconnaissance(params)
            elif stage_name == "vulnerability_assessment":
                self._run_vulnerability_assessment(recon_data, params)
            elif stage_name == "system_assessment":
                self._run_system_assessment(params)
            elif stage_name == "anonymity":
                self._run_anonymity(params)
            elif stage_name == "forensics":
                self._run_forensics(params)

            self.results["stages_executed"].append(stage_name)

        # Generate final consolidated deliverables if enabled
        if self.data.get("reporting", {}).get("enabled", True):
            self._generate_reports()

        self.logger.info(f"Scenario {self.scenario_id} completed successfully.")
        return self.results

    def _run_reconnaissance(self, params: dict[str, Any]) -> dict[str, Any]:
        ports = params.get("ports")
        timeout = float(params.get("timeout", 0.5))
        scanner = ReconScanner(validator=self.validator, timeout=timeout)

        scope_targets = self.data.get("scope", {}).get("targets", ["127.0.0.1"])
        primary_target = scope_targets[0]

        if "/" in primary_target:
            recon_data = scanner.scan_range(primary_target, ports=ports)
        else:
            host_res = scanner.scan_host(primary_target, ports=ports)
            recon_data = {
                "module": "reconnaissance",
                "target": primary_target,
                "findings": [host_res] if host_res["open_ports_count"] > 0 else [],
            }

        out_file = self.output_dir / "recon.json"
        out_file.write_text(json.dumps(recon_data, indent=2), encoding="utf-8")
        self._vault_artifact(out_file, "Network reconnaissance findings")
        return recon_data

    def _run_vulnerability_assessment(
        self, recon_data: dict[str, Any] | None, params: dict[str, Any]
    ) -> dict[str, Any]:
        scanner = VulnerabilityScanner(validator=self.validator)
        input_data = recon_data or {"target": "127.0.0.1", "findings": []}
        vuln_res = scanner.scan_recon_results(input_data)

        out_file = self.output_dir / "vuln.json"
        out_file.write_text(json.dumps(vuln_res, indent=2), encoding="utf-8")
        self._vault_artifact(out_file, "Vulnerability scan CVE findings")
        return vuln_res

    def _run_system_assessment(self, params: dict[str, Any]) -> dict[str, Any]:
        target_root = params.get("target_root", "/")
        auditor = SystemAuditor(root_dir=target_root)
        audit_res = auditor.run_full_audit()

        if params.get("check_compliance", True):
            eval_res = ComplianceEvaluator.evaluate(audit_res)
            audit_res["compliance"] = eval_res

        out_file = self.output_dir / "system.json"
        out_file.write_text(json.dumps(audit_res, indent=2), encoding="utf-8")
        self._vault_artifact(out_file, "System security audit and compliance findings")
        return audit_res

    def _run_anonymity(self, params: dict[str, Any]) -> dict[str, Any]:
        auditor = AntiForensicsAuditor()
        env_res = auditor.run_environment_audit()

        leak = DNSLeakPrevention()
        env_res["dns_leak"] = leak.audit_leak_defense_posture()

        out_file = self.output_dir / "anonymity.json"
        out_file.write_text(json.dumps(env_res, indent=2), encoding="utf-8")
        self._vault_artifact(out_file, "Anonymity and anti-forensics posture log")
        return env_res

    def _run_forensics(self, params: dict[str, Any]) -> dict[str, Any]:
        target_dir = params.get("timeline_target", self.output_dir)
        tg = TimelineGenerator()
        events = tg.generate_timeline(target_dir, max_entries=500)

        csv_file = self.output_dir / "timeline.csv"
        tg.export_csv(events, csv_file)
        self._vault_artifact(csv_file, "Forensic activity timeline CSV")

        forensic_res = {
            "module": "forensics",
            "timeline_events_count": len(events),
            "timeline_csv": str(csv_file),
        }
        out_file = self.output_dir / "forensics.json"
        out_file.write_text(json.dumps(forensic_res, indent=2), encoding="utf-8")
        self._vault_artifact(out_file, "Forensic investigation metadata")
        return forensic_res

    def _vault_artifact(self, file_path: Path, description: str) -> None:
        if self.data.get("evidence", {}).get("auto_collect", True):
            meta = self.collector.collect(
                source_file=file_path,
                description=description,
                custodian=self.operator,
                case_id=self.case_id,
            )
            self.results["artifacts_collected"].append(meta["evidence_id"])

    def _generate_reports(self) -> None:
        engine = ReportEngine.from_directory(self.output_dir, case_id=self.case_id)
        engine.data.operator = self.operator
        engine.data.lab_name = self.lab_name
        engine.data.title = f"RedBoot Assessment Report — {self.scenario_name}"

        formats = self.data.get("reporting", {}).get(
            "formats", ["html", "markdown", "json"]
        )

        if "html" in formats:
            html = HTMLFormatter.format_report(engine.data)
            (self.output_dir / "report.html").write_text(html, encoding="utf-8")

        if "markdown" in formats:
            md = MarkdownFormatter.format_report(engine.data)
            (self.output_dir / "report.md").write_text(md, encoding="utf-8")

        if "json" in formats:
            js = JSONFormatter.format_report(engine.data)
            (self.output_dir / "report.json").write_text(js, encoding="utf-8")


@click.command(name="redboot-scenario-runner")
@click.option(
    "--scenario",
    "-s",
    required=True,
    help="Path to scenario YAML definition.",
)
@click.option(
    "--output-dir",
    "-o",
    default=None,
    help="Target directory for output files and evidence vault.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Validate scope and configuration without executing active checks.",
)
def main(scenario: str, output_dir: str | None, dry_run: bool) -> None:
    """Execute scripted laboratory security scenarios with scope enforcement."""
    logger = get_logger("scenario-runner-cli")
    try:
        runner = ScenarioRunner(scenario_path=scenario, output_dir=output_dir)
        click.echo(
            f"[*] Initialized Scenario: {runner.scenario_name} [{runner.scenario_id}]"
        )
        click.echo(f"[*] Case ID: {runner.case_id} | Operator: {runner.operator}")

        results = runner.execute_all(dry_run=dry_run)
        click.echo(
            f"[+] Completed! Stages executed: {', '.join(results['stages_executed']) or 'None (dry-run)'}"
        )
        click.echo(f"[+] Output Directory: {runner.output_dir}")
        click.echo(f"[+] Artifacts Vaulted: {len(results['artifacts_collected'])}")

    except ScopeViolation as sv:
        logger.error(f"Scenario aborted due to scope violation: {sv}")
        click.echo(f"Error: {sv}", err=True)
        sys.exit(2)
    except Exception as e:
        logger.error(f"Scenario execution failed: {e}")
        click.echo(f"Execution Error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
