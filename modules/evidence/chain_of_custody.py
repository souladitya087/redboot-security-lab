"""
RedBoot Cryptographic Chain of Custody Ledger

Provides an append-only, tamper-evident custody log where every event is cryptographically
linked to the previous entry using SHA-256 block hashing.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


@dataclass
class CustodyEntry:
    entry_id: int
    timestamp: str
    evidence_id: str
    action: str
    custodian: str
    evidence_sha256: str
    notes: str
    prev_hash: str
    record_hash: str = ""

    def calculate_hash(self) -> str:
        payload = (
            f"{self.entry_id}|{self.timestamp}|{self.evidence_id}|{self.action}|"
            f"{self.custodian}|{self.evidence_sha256}|{self.notes}|{self.prev_hash}"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ChainOfCustody:
    """Manages the append-only cryptographic custody ledger."""

    def __init__(self, ledger_file: str | Path) -> None:
        self.ledger_file = Path(ledger_file)
        self.entries: list[CustodyEntry] = []
        self._load()

    def _load(self) -> None:
        if not self.ledger_file.exists():
            return
        try:
            with open(self.ledger_file, "r", encoding="utf-8") as f:
                raw_entries = json.load(f)
                self.entries = [CustodyEntry(**e) for e in raw_entries]
        except Exception:
            self.entries = []

    def _save(self) -> None:
        self.ledger_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.ledger_file, "w", encoding="utf-8") as f:
            json.dump([asdict(e) for e in self.entries], f, indent=2)

    def add_entry(
        self,
        evidence_id: str,
        action: str,
        custodian: str,
        evidence_sha256: str,
        notes: str = "",
    ) -> CustodyEntry:
        """Append a new verified record to the custody ledger."""
        entry_id = len(self.entries) + 1
        timestamp = datetime.now(timezone.utc).isoformat()
        prev_hash = self.entries[-1].record_hash if self.entries else GENESIS_HASH

        entry = CustodyEntry(
            entry_id=entry_id,
            timestamp=timestamp,
            evidence_id=evidence_id,
            action=action.upper(),
            custodian=custodian,
            evidence_sha256=evidence_sha256,
            notes=notes,
            prev_hash=prev_hash,
        )
        entry.record_hash = entry.calculate_hash()
        self.entries.append(entry)
        self._save()
        return entry

    def verify_integrity(self) -> tuple[bool, str]:
        """
        Verify the entire chain of custody ledger.
        Ensures all hashes match their content and link consecutively without gaps.
        """
        if not self.entries:
            return True, "Ledger is empty."

        expected_prev = GENESIS_HASH
        for i, entry in enumerate(self.entries):
            # Check previous hash link
            if entry.prev_hash != expected_prev:
                return (
                    False,
                    f"Broken chain link at entry #{entry.entry_id}: prev_hash mismatch.",
                )

            # Check record hash calculation
            expected_hash = entry.calculate_hash()
            if entry.record_hash != expected_hash:
                return (
                    False,
                    f"Tampered record at entry #{entry.entry_id}: recorded hash does not match computed content.",
                )

            expected_prev = entry.record_hash

        return (
            True,
            f"Chain of custody verified intact across {len(self.entries)} entries.",
        )

    def get_history_for_evidence(self, evidence_id: str) -> list[dict[str, Any]]:
        """Return all lifecycle custody entries for a specific evidence item."""
        return [asdict(e) for e in self.entries if e.evidence_id == evidence_id]
