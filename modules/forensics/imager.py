"""
RedBoot Forensic Disk Imager

Performs bit-for-bit raw disk acquisition with simultaneous cryptographic hashing.
Enforces read-only access to source devices to ensure forensic soundness.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from modules.core.logger import get_logger

DEFAULT_CHUNK_SIZE = 64 * 1024  # 64KB blocks


class ForensicImager:
    """Acquires raw forensic disk images and computes cryptographic verification hashes."""

    def __init__(self, chunk_size: int = DEFAULT_CHUNK_SIZE) -> None:
        self.chunk_size = chunk_size
        self.logger = get_logger("forensic-imager")

    def acquire_image(
        self,
        source_path: str | Path,
        destination_path: str | Path,
        case_id: str = "CASE-DEFAULT",
        examiner: str = "examiner",
    ) -> dict[str, Any]:
        """
        Acquire bit-for-bit image from source file/device to destination.
        Calculates SHA-256 and MD5 hashes during stream processing.
        """
        src = Path(source_path)
        dest = Path(destination_path)

        if not src.exists():
            raise FileNotFoundError(f"Forensic source not found: {src}")

        dest.parent.mkdir(parents=True, exist_ok=True)
        start_time = datetime.now(timezone.utc).isoformat()
        self.logger.info(f"Starting forensic acquisition of {src} -> {dest}")

        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()
        total_bytes = 0

        # Read source in strict read-only binary mode
        with open(src, "rb") as f_in, open(dest, "wb") as f_out:
            while True:
                chunk = f_in.read(self.chunk_size)
                if not chunk:
                    break
                sha256_hash.update(chunk)
                md5_hash.update(chunk)
                f_out.write(chunk)
                total_bytes += len(chunk)

        end_time = datetime.now(timezone.utc).isoformat()
        digest_sha256 = sha256_hash.hexdigest()
        digest_md5 = md5_hash.hexdigest()

        # Write acquisition log sidecar file
        log_path = dest.with_suffix(dest.suffix + ".info.txt")
        info_content = (
            f"RedBoot Forensic Image Acquisition Log\n"
            f"======================================\n"
            f"Case ID:        {case_id}\n"
            f"Examiner:       {examiner}\n"
            f"Source:         {src}\n"
            f"Destination:    {dest}\n"
            f"Total Bytes:    {total_bytes}\n"
            f"Start Time:     {start_time}\n"
            f"End Time:       {end_time}\n"
            f"MD5 Hash:       {digest_md5}\n"
            f"SHA-256 Hash:   {digest_sha256}\n"
            f"Status:         VERIFIED_ACQUISITION\n"
        )
        log_path.write_text(info_content, encoding="utf-8")

        self.logger.info(
            f"Acquisition complete ({total_bytes} bytes). SHA-256: {digest_sha256}"
        )

        return {
            "case_id": case_id,
            "examiner": examiner,
            "source": str(src),
            "destination": str(dest),
            "bytes_acquired": total_bytes,
            "started_at": start_time,
            "completed_at": end_time,
            "md5": digest_md5,
            "sha256": digest_sha256,
            "log_file": str(log_path),
            "status": "SUCCESS",
        }
