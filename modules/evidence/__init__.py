"""
RedBoot Evidence Collection Module

Evidence acquisition, SHA-256/SHA-512 fingerprinting, and tamper-evident
append-only Chain of Custody tracking.
"""

from modules.evidence.chain_of_custody import ChainOfCustody, CustodyEntry
from modules.evidence.collector import EvidenceCollector
from modules.evidence.verifier import EvidenceVerifier

__all__ = [
    "EvidenceCollector",
    "ChainOfCustody",
    "CustodyEntry",
    "EvidenceVerifier",
]
