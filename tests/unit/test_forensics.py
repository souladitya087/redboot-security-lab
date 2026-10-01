"""
Unit tests for Digital Forensics Module.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from modules.forensics.carver import FileCarver
from modules.forensics.imager import ForensicImager
from modules.forensics.log_analyzer import LogAnalyzer
from modules.forensics.timeline import TimelineGenerator


class TestForensicImager:
    def test_acquire_image_computes_hashes(self, tmp_path: Path):
        source = tmp_path / "raw_disk.bin"
        sample_data = b"RedBoot Forensic Test Disk Sector Data \x00\x01\x02\x03" * 100
        source.write_bytes(sample_data)

        dest = tmp_path / "output_image.dd"
        imager = ForensicImager()
        res = imager.acquire_image(
            source, dest, case_id="CASE-TEST-01", examiner="analyst"
        )

        assert res["status"] == "SUCCESS"
        assert res["bytes_acquired"] == len(sample_data)
        assert res["sha256"] == hashlib.sha256(sample_data).hexdigest()
        assert res["md5"] == hashlib.md5(sample_data).hexdigest()
        assert dest.exists()
        assert Path(res["log_file"]).exists()


class TestFileCarver:
    def test_carve_embedded_png_and_pdf(self, tmp_path: Path):
        img_file = tmp_path / "disk.img"
        out_dir = tmp_path / "carved"

        png_content = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR...test_png_data...\x49\x45\x4e\x44\xae\x42\x60\x82"
        pdf_content = b"%PDF-1.4\n1 0 obj...test_pdf_data...\n%%EOF"
        padding = b"\x00" * 512

        raw_disk_data = padding + png_content + padding + pdf_content + padding
        img_file.write_bytes(raw_disk_data)

        carver = FileCarver()
        findings = carver.carve_file(img_file, out_dir)

        extensions = [f["extension"] for f in findings]
        assert "png" in extensions
        assert "pdf" in extensions
        assert len(findings) == 2


class TestTimelineGenerator:
    def test_timeline_generation_and_export(self, tmp_path: Path):
        test_dir = tmp_path / "evidence_dir"
        test_dir.mkdir()
        (test_dir / "file1.txt").write_text("Hello", encoding="utf-8")
        (test_dir / "file2.txt").write_text("World", encoding="utf-8")

        tg = TimelineGenerator()
        events = tg.generate_timeline(test_dir)
        assert len(events) >= 6  # 2 files * at least 3 timestamps each

        csv_path = tmp_path / "timeline.csv"
        tg.export_csv(events, csv_path)
        assert csv_path.exists()
        assert csv_path.stat().st_size > 0


class TestLogAnalyzer:
    def test_auth_log_analysis(self, tmp_path: Path):
        auth_log = tmp_path / "auth.log"
        lines = [
            "Oct  1 10:00:01 lab sshd[101]: Failed password for root from 192.168.56.99 port 51234 ssh2",
            "Oct  1 10:00:02 lab sshd[102]: Failed password for root from 192.168.56.99 port 51235 ssh2",
            "Oct  1 10:00:03 lab sshd[103]: Failed password for root from 192.168.56.99 port 51236 ssh2",
            "Oct  1 10:00:04 lab sshd[104]: Failed password for root from 192.168.56.99 port 51237 ssh2",
            "Oct  1 10:00:05 lab sshd[105]: Failed password for root from 192.168.56.99 port 51238 ssh2",
            "Oct  1 10:00:10 lab sudo:  operator : TTY=pts/0 ; PWD=/home/operator ; USER=root ; COMMAND=/bin/bash",
            "Oct  1 10:00:15 lab sshd[110]: Accepted password for student from 192.168.56.10 port 49100 ssh2",
        ]
        auth_log.write_text("\n".join(lines), encoding="utf-8")

        analyzer = LogAnalyzer()
        res = analyzer.analyze_auth_log(auth_log)

        assert res["lines_parsed"] == 7
        assert len(res["brute_force_alerts"]) == 1
        assert res["brute_force_alerts"][0]["target"] == "root@192.168.56.99"
        assert len(res["sudo_executions"]) == 1
        assert res["sudo_executions"][0]["user"] == "operator"
        assert len(res["successful_logins"]) == 1
