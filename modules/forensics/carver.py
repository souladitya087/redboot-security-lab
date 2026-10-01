"""
RedBoot File Carver

Recovers files from raw binary data, unallocated space, or disk images
using file signature analysis (magic bytes).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from modules.core.logger import get_logger


@dataclass
class FileSignature:
    extension: str
    mime: str
    header: bytes
    footer: bytes | None = None
    max_size: int = 10 * 1024 * 1024  # Default 10MB max extraction


DEFAULT_SIGNATURES: list[FileSignature] = [
    FileSignature(
        extension="png",
        mime="image/png",
        header=b"\x89PNG\r\n\x1a\n",
        footer=b"\x49\x45\x4e\x44\xae\x42\x60\x82",
    ),
    FileSignature(
        extension="jpg",
        mime="image/jpeg",
        header=b"\xff\xd8\xff",
        footer=b"\xff\xd9",
    ),
    FileSignature(
        extension="pdf",
        mime="application/pdf",
        header=b"%PDF-",
        footer=b"%%EOF",
    ),
    FileSignature(
        extension="zip",
        mime="application/zip",
        header=b"PK\x03\x04",
        footer=b"PK\x05\x06",
    ),
    FileSignature(
        extension="elf",
        mime="application/x-executable",
        header=b"\x7fELF",
        max_size=5 * 1024 * 1024,
    ),
    FileSignature(
        extension="sqlite",
        mime="application/x-sqlite3",
        header=b"SQLite format 3\x00",
        max_size=20 * 1024 * 1024,
    ),
]


class FileCarver:
    """Carves files from raw forensic images using magic byte signatures."""

    def __init__(self, signatures: list[FileSignature] | None = None) -> None:
        self.signatures = signatures or DEFAULT_SIGNATURES
        self.logger = get_logger("file-carver")

    def carve_file(
        self,
        image_path: str | Path,
        output_dir: str | Path,
    ) -> list[dict[str, Any]]:
        """
        Carve files from an image and save extracted artifacts to output_dir.
        """
        img = Path(image_path)
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        if not img.exists():
            raise FileNotFoundError(f"Image not found: {img}")

        self.logger.info(f"Starting file carving on {img}...")
        data = img.read_bytes()
        carved_records: list[dict[str, Any]] = []

        file_counter = 0
        for sig in self.signatures:
            start_pos = 0
            while True:
                pos = data.find(sig.header, start_pos)
                if pos == -1:
                    break

                extracted_data: bytes | None = None
                if sig.footer:
                    footer_pos = data.find(sig.footer, pos + len(sig.header))
                    if footer_pos != -1:
                        end_pos = footer_pos + len(sig.footer)
                        extracted_size = end_pos - pos
                        if extracted_size <= sig.max_size:
                            extracted_data = data[pos:end_pos]
                else:
                    # Header-only match: carve up to max_size or until next 512-byte boundary
                    end_boundary = pos + min(sig.max_size, 65536)
                    extracted_data = data[pos:end_boundary]

                if extracted_data:
                    file_counter += 1
                    file_name = f"carved_{file_counter:04d}_{pos:08x}.{sig.extension}"
                    file_dest = out / file_name
                    file_dest.write_bytes(extracted_data)

                    file_hash = hashlib.sha256(extracted_data).hexdigest()
                    carved_records.append(
                        {
                            "file_name": file_name,
                            "path": str(file_dest),
                            "offset": pos,
                            "size": len(extracted_data),
                            "extension": sig.extension,
                            "mime": sig.mime,
                            "sha256": file_hash,
                        }
                    )

                start_pos = pos + len(sig.header)

        self.logger.info(f"Carving finished: {len(carved_records)} files recovered.")
        return carved_records
