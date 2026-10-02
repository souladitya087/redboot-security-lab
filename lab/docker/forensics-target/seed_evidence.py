"""
RedBoot Forensics Target Seed Generator

Populates mock disk images, logs, and filesystem artifacts for forensic testing.
"""

from pathlib import Path


def generate_artifacts(dest_dir: str = "/mnt/evidence"):
    base = Path(dest_dir)
    base.mkdir(parents=True, exist_ok=True)

    # 1. Create mock raw disk with embedded PNG and PDF for file carving
    png_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR...redboot_flag_png...\x49\x45\x4e\x44\xae\x42\x60\x82"
    pdf_data = b"%PDF-1.4\n1 0 obj...confidential_assessment_memo...\n%%EOF"
    disk_data = (
        (b"\x00" * 2048) + png_data + (b"\x00" * 4096) + pdf_data + (b"\x00" * 1024)
    )
    disk_path = base / "target_disk.raw"
    disk_path.write_bytes(disk_data)
    print(f"[+] Created raw disk image: {disk_path} ({len(disk_data)} bytes)")

    # 2. Create mock auth.log with brute force and sudo abuse
    log_content = (
        "Oct  2 08:00:01 lab sshd[201]: Failed password for root from 192.168.56.99 port 41234 ssh2\n"
        "Oct  2 08:00:02 lab sshd[202]: Failed password for root from 192.168.56.99 port 41235 ssh2\n"
        "Oct  2 08:00:03 lab sshd[203]: Failed password for root from 192.168.56.99 port 41236 ssh2\n"
        "Oct  2 08:00:04 lab sshd[204]: Failed password for root from 192.168.56.99 port 41237 ssh2\n"
        "Oct  2 08:00:05 lab sshd[205]: Failed password for root from 192.168.56.99 port 41238 ssh2\n"
        "Oct  2 08:01:10 lab sudo:  operator : TTY=pts/0 ; PWD=/home/operator ; USER=root ; COMMAND=/bin/bash\n"
        "Oct  2 08:02:15 lab sshd[210]: Accepted password for admin from 192.168.56.10 port 49100 ssh2\n"
    )
    log_path = base / "auth.log"
    log_path.write_text(log_content, encoding="utf-8")
    print(f"[+] Created mock auth log: {log_path}")

    # 3. Create mock offline filesystem root
    mock_root = base / "target_fs"
    (mock_root / "etc").mkdir(parents=True, exist_ok=True)
    (mock_root / "bin").mkdir(parents=True, exist_ok=True)

    passwd = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "backdoor:x:0:0:evil_admin:/root:/bin/bash\n"
        "user1:x:1000:1000:standard_user:/home/user1:/bin/bash\n"
    )
    (mock_root / "etc" / "passwd").write_text(passwd, encoding="utf-8")

    shadow = "root:$6$rounds=5000$...:19000:0:99999:7:::\n"
    (mock_root / "etc" / "shadow").write_text(shadow, encoding="utf-8")

    find_bin = mock_root / "bin" / "find"
    find_bin.write_text('#!/bin/sh\nexec /bin/sh "$@"\n', encoding="utf-8")

    print(f"[+] Created mock target filesystem at {mock_root}")


if __name__ == "__main__":
    generate_artifacts()
    # Keep container alive
    import time

    while True:
        time.sleep(3600)
