"""
Unit tests for Evidence Collection & Chain of Custody Module.
"""

from __future__ import annotations

import json
from pathlib import Path

from modules.evidence.chain_of_custody import ChainOfCustody
from modules.evidence.collector import EvidenceCollector
from modules.evidence.verifier import EvidenceVerifier


class TestChainOfCustody:
    def test_ledger_append_and_verify(self, tmp_path: Path):
        ledger_file = tmp_path / "custody.json"
        custody = ChainOfCustody(ledger_file)

        custody.add_entry(
            evidence_id="EVD-001",
            action="INGESTED",
            custodian="investigator-1",
            evidence_sha256="abc12345",
            notes="Initial intake",
        )
        custody.add_entry(
            evidence_id="EVD-001",
            action="TRANSFERRED",
            custodian="analyst-2",
            evidence_sha256="abc12345",
            notes="Transfer for carving",
        )

        valid, msg = custody.verify_integrity()
        assert valid is True
        assert len(custody.entries) == 2

    def test_tamper_detection_in_ledger(self, tmp_path: Path):
        ledger_file = tmp_path / "custody.json"
        custody = ChainOfCustody(ledger_file)

        custody.add_entry(
            evidence_id="EVD-001",
            action="INGESTED",
            custodian="investigator-1",
            evidence_sha256="abc12345",
        )
        custody.add_entry(
            evidence_id="EVD-002",
            action="INGESTED",
            custodian="investigator-1",
            evidence_sha256="def67890",
        )

        # Deliberately tamper with raw ledger file on disk
        data = json.loads(ledger_file.read_text(encoding="utf-8"))
        data[0]["custodian"] = "malicious_actor"  # Tamper with first block
        ledger_file.write_text(json.dumps(data), encoding="utf-8")

        # Reload and verify
        reloaded = ChainOfCustody(ledger_file)
        valid, msg = reloaded.verify_integrity()
        assert valid is False
        assert "Tampered" in msg or "Broken" in msg


class TestEvidenceCollectorAndVerifier:
    def test_collect_and_verify_vault(self, tmp_path: Path):
        vault_dir = tmp_path / "vault"
        sample_file = tmp_path / "recon_scan.json"
        sample_file.write_text('{"module": "reconnaissance"}', encoding="utf-8")

        collector = EvidenceCollector(vault_dir=vault_dir)
        meta = collector.collect(
            source_file=sample_file,
            description="Network scan output",
            custodian="operator",
            case_id="CASE-2026-001",
        )

        assert meta["evidence_id"].startswith("EVD-")
        assert len(meta["sha256"]) == 64
        assert len(meta["sha512"]) == 128

        verifier = EvidenceVerifier(vault_dir=vault_dir)
        report = verifier.verify_vault()
        assert report["overall_integrity_verified"] is True
        assert report["chain_of_custody_status"] == "VALID"
        assert report["all_file_hashes_match"] is True

    def test_tampered_file_detection(self, tmp_path: Path):
        vault_dir = tmp_path / "vault"
        sample_file = tmp_path / "data.txt"
        sample_file.write_text("Authentic evidence data", encoding="utf-8")

        collector = EvidenceCollector(vault_dir=vault_dir)
        meta = collector.collect(
            source_file=sample_file,
            description="Important test file",
        )

        vaulted_file = Path(meta["vault_path"])
        # Alter the vaulted file contents behind the scenes
        vaulted_file.write_text("MODIFIED / TAMPERED EVIDENCE CONTENT", encoding="utf-8")

        verifier = EvidenceVerifier(vault_dir=vault_dir)
        report = verifier.verify_vault()
        assert report["overall_integrity_verified"] is False
        assert report["all_file_hashes_match"] is False
