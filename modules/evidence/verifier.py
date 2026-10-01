"""
RedBoot Evidence Integrity Verifier

Validates that files in the evidence vault match their recorded cryptographic hashes
and verifies that the chain of custody has not been tampered with or modified.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from modules.core.logger import get_logger
from modules.evidence.chain_of_custody import ChainOfCustody
from modules.evidence.collector import EvidenceCollector


class EvidenceVerifier:
    """Verifies evidence integrity and chain-of-custody validity."""

    def __init__(self, vault_dir: str | Path = "evidence_vault") -> None:
        self.vault_dir = Path(vault_dir)
        self.logger = get_logger("evidence-verifier")

    def verify_vault(self) -> dict[str, Any]:
        """
        Verify all evidence items in vault:
        1. Chain of custody ledger hash chain
        2. File SHA-256 and SHA-512 match against metadata.json
        """
        ledger_path = self.vault_dir / "chain_of_custody.json"
        custody = ChainOfCustody(ledger_path)
        ledger_valid, ledger_msg = custody.verify_integrity()

        item_verifications: list[dict[str, Any]] = []
        all_files_valid = True

        for meta_file in sorted(self.vault_dir.glob("EVD-*/metadata.json")):
            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
                evidence_id = meta["evidence_id"]
                file_name = meta["file_name"]
                expected_sha256 = meta["sha256"]
                expected_sha512 = meta["sha512"]

                stored_file = meta_file.parent / file_name
                if not stored_file.exists():
                    item_verifications.append(
                        {
                            "evidence_id": evidence_id,
                            "status": "FAIL",
                            "error": f"Artifact file '{file_name}' missing from vault directory.",
                        }
                    )
                    all_files_valid = False
                    continue

                actual_sha256, actual_sha512 = EvidenceCollector.compute_hashes(
                    stored_file
                )
                match_256 = actual_sha256 == expected_sha256
                match_512 = actual_sha512 == expected_sha512
                is_valid = match_256 and match_512

                if not is_valid:
                    all_files_valid = False

                item_verifications.append(
                    {
                        "evidence_id": evidence_id,
                        "file_name": file_name,
                        "sha256_match": match_256,
                        "sha512_match": match_512,
                        "status": "PASS" if is_valid else "FAIL_HASH_MISMATCH",
                    }
                )
            except Exception as e:
                all_files_valid = False
                item_verifications.append({"status": "ERROR", "error": str(e)})

        overall_valid = ledger_valid and all_files_valid

        return {
            "overall_integrity_verified": overall_valid,
            "chain_of_custody_status": "VALID" if ledger_valid else "COMPROMISED",
            "chain_of_custody_message": ledger_msg,
            "total_items_checked": len(item_verifications),
            "all_file_hashes_match": all_files_valid,
            "evidence_items": item_verifications,
        }
