"""
RedBoot Evidence Collector

Collects, vaults, and cryptographically fingerprints forensic artifacts and assessment data.
Maintains tamper-evident metadata and chain-of-custody tracking.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from modules.core.logger import get_logger
from modules.evidence.chain_of_custody import ChainOfCustody


class EvidenceCollector:
    """Ingests and catalogues digital evidence items into a secure vault."""

    def __init__(self, vault_dir: str | Path = "evidence_vault") -> None:
        self.vault_dir = Path(vault_dir)
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.ledger_file = self.vault_dir / "chain_of_custody.json"
        self.custody = ChainOfCustody(self.ledger_file)
        self.logger = get_logger("evidence-collector")

    @staticmethod
    def compute_hashes(file_path: Path) -> tuple[str, str]:
        """Compute SHA-256 and SHA-512 hashes for a file."""
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
                sha512.update(chunk)
        return sha256.hexdigest(), sha512.hexdigest()

    def collect(
        self,
        source_file: str | Path,
        description: str,
        custodian: str = "operator",
        case_id: str = "DEFAULT-CASE",
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Ingest a file into the evidence vault.
        """
        src = Path(source_file)
        if not src.exists():
            raise FileNotFoundError(f"Source file to collect does not exist: {src}")

        timestamp = datetime.now(timezone.utc).isoformat()
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d")

        # Count existing items in vault to generate serial ID
        existing_items = list(self.vault_dir.glob("EVD-*"))
        evidence_id = f"EVD-{date_str}-{len(existing_items) + 1:04d}"

        item_dir = self.vault_dir / evidence_id
        item_dir.mkdir(parents=True, exist_ok=True)

        dest_file = item_dir / src.name
        shutil.copy2(src, dest_file)

        # Compute cryptographic fingerprints on vaulted file
        sha256, sha512 = self.compute_hashes(dest_file)

        # Build metadata descriptor
        metadata: dict[str, Any] = {
            "evidence_id": evidence_id,
            "case_id": case_id,
            "collected_at": timestamp,
            "custodian": custodian,
            "description": description,
            "source_path": str(src.resolve()),
            "vault_path": str(dest_file.resolve()),
            "file_name": src.name,
            "file_size": dest_file.stat().st_size,
            "sha256": sha256,
            "sha512": sha512,
            "tags": tags or [],
        }

        # Write metadata JSON
        meta_path = item_dir / "metadata.json"
        meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

        # Record in cryptographic Chain of Custody ledger
        self.custody.add_entry(
            evidence_id=evidence_id,
            action="INGESTED",
            custodian=custodian,
            evidence_sha256=sha256,
            notes=f"Initial ingestion into evidence vault: {description}",
        )

        self.logger.info(
            f"Evidence {evidence_id} collected successfully. SHA-256: {sha256}"
        )
        return metadata

    def list_evidence(self) -> list[dict[str, Any]]:
        """List all evidence metadata stored in the vault."""
        items: list[dict[str, Any]] = []
        for meta_file in sorted(self.vault_dir.glob("EVD-*/metadata.json")):
            try:
                items.append(json.loads(meta_file.read_text(encoding="utf-8")))
            except Exception:
                pass
        return items
