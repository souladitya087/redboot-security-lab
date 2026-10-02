# RedBoot Operator Handbook & Laboratory Guide
## Practical Guide for Live Assessment, Digital Forensics, and Lab Exercises

**Version:** 1.0.0  
**Target Environment:** Debian 12 Bookworm Live OS / Docker Isolated Lab  
**Audience:** Security Students, Academic Researchers, Forensic Analysts, Penetration Testers  
**Notice:** Authorized Laboratory Use Only  

---

## 1. Introduction & Architecture Overview

**RedBoot** is a self-contained, live bootable security platform built on Debian 12 Bookworm. It is engineered to perform non-destructive endpoint assessment, rapid vulnerability identification, write-blocked digital forensics, and cryptographically verified evidence custody.

```
+-----------------------------------------------------------------------------------+
|                           RedBoot Unified Operator Flow                           |
|                                                                                   |
|  [ Boot USB Media ]  -->  [ Hardware Write-Block ]  -->  [ Scope Verification ]    |
|                                                                  |                |
|  +--------------------+---------------------+--------------------+                |
|  |                    |                     |                                     |
|  v                    v                     v                                     |
| [ Recon & Vuln ]    [ System Audit ]      [ Forensic Imager ]                     |
|  |                    |                     |                                     |
|  +--------------------+---------------------+                                     |
|                       |                                                           |
|                       v                                                           |
|            [ SHA-256 Evidence Vault ]                                             |
|                       |                                                           |
|                       v                                                           |
|       [ Append-Only Chain-of-Custody ]                                            |
|                       |                                                           |
|                       v                                                           |
|         [ HTML / Markdown / JSON Report ]                                         |
+-----------------------------------------------------------------------------------+
```

---

## 2. Preparing Bootable Media

### 2.1 Hardware Requirements
- **Architecture:** x86_64 (64-bit AMD/Intel)
- **Memory (RAM):** 4 GB minimum (8 GB recommended for RAM-only `toram` mode)
- **USB Drive:** 8 GB or larger USB 3.0/3.1 flash drive
- **Firmware:** UEFI with Secure Boot support or Legacy BIOS

### 2.2 Generating the ISO Image
From a Debian/Ubuntu system or Docker container:
```bash
# Clone the repository
git clone https://github.com/souladitya087/redboot-security-lab.git
cd redboot-security-lab

# Run the ISO builder script
sudo bash scripts/build_iso.sh
```
The output file `redboot-live-amd64.iso` will be generated in `output/iso/`.

### 2.3 Flashing the USB Drive

#### On Linux / macOS (using `dd`):
```bash
# Identify your USB drive device path (e.g., /dev/sdb — DO NOT SELECT YOUR SYSTEM DRIVE!)
lsblk

# Write the ISO image directly
sudo dd if=output/iso/redboot-live-amd64.iso of=/dev/sdX bs=4M status=progress conv=fdatasync
```

#### On Windows (using Rufus):
1. Insert the USB drive and launch **Rufus**.
2. Select your USB drive under **Device**.
3. Click **SELECT** and choose `redboot-live-amd64.iso`.
4. Partition scheme: **GPT** | Target system: **UEFI (non-CSM)**.
5. Click **START** and select **Write in DD Image mode** when prompted.

#### Using Ventoy:
1. Install [Ventoy](https://www.ventoy.net/) onto your USB drive.
2. Copy `redboot-live-amd64.iso` directly into the root partition of the Ventoy drive.

---

## 3. Booting the RedBoot Live Environment

1. Insert the prepared USB drive into the target lab workstation.
2. Power on the system and repeatedly press the **Boot Menu Key** (typically `F12` on Dell/Lenovo, `F11` on MSI, `F8` on ASUS, or `Esc` on HP).
3. Select your USB drive from the UEFI Boot Selection menu.
4. The **RedBoot GRUB Menu** presents three operational modes:

| Boot Option | Kernel Parameters | Intended Use Case |
|---|---|---|
| **RedBoot Live — Standard (RAM Mode)** | `boot=live components toram quiet splash` | Loads entire distribution into RAM. USB drive can be safely unplugged. |
| **RedBoot Forensics — Read-Only Mode** | `boot=live components ro noload noatime` | Hardware write-blocking enabled on all block storage. Zero-touch forensic imaging. |
| **RedBoot Stealth — Tor & MAC Spoof** | `boot=live components tor_enforced mac_random=1` | Automatic MAC rotation and SOCKS5 Tor routing for anonymity exercises. |

---

## 4. Interactive Console Dashboard (`redboot-menu.sh`)

For live terminal operations without entering full Python commands, launch the interactive text-based console menu:

```bash
sudo /opt/redboot/boot/scripts/redboot-menu.sh
```

### Dashboard Features:
1. **[1] Mount Target Drive (Read-Only):** Safely mounts target SATA/NVMe drive with write-block protection (`ro,noload,noatime`).
2. **[2] Hardware Security Audit:** Inspects UEFI Secure Boot status, PCIe buses, and peripheral security.
3. **[3] Network Reconnaissance:** Scans the authorized lab subnet for live hosts, ports, and banners.
4. **[4] Vulnerability Scanner:** Matches banners against known CVEs and calculates CVSS v3.1 scores.
5. **[5] Digital Forensics Imager:** Creates split bit-for-bit raw disk images with continuous SHA-256 chunk hashing.
6. **[6] Magic-Byte File Carver:** Recovers deleted PNG, PDF, ZIP, and JPEG artifacts from raw disk space.
7. **[7] Chain of Custody & Vault Status:** Displays immutable ledger entries and verifies SHA-256 fingerprints.
8. **[8] Generate Consolidated Reports:** Exports HTML dashboard, Markdown briefing, and JSON data.
9. **[0] Exit / Shutdown**

---

## 5. Unified Command-Line Interface (`redboot.py`)

RedBoot provides a unified top-level command-line tool (`redboot.py`) accessible across all modules:

```bash
python redboot.py [COMMAND] [OPTIONS]
```

### 5.1 Platform Status Check
```bash
python redboot.py status
```
Outputs the operational readiness of all core engines (Recon, Audit, Vuln, Forensics, Evidence Vault, Reporting).

### 5.2 Network Reconnaissance (`recon`)
Scan an authorized host or CIDR subnet:
```bash
# Scan single host with top ports
python redboot.py recon scan -t 192.168.56.10 -p 21,22,80,443,3306,8080 -o output/recon.json

# Scan full lab subnet with banner grabbing
python redboot.py recon scan -t 192.168.56.0/24 --timeout 0.5 -o output/recon_subnet.json
```

### 5.3 System Security Audit (`audit`)
Perform an offline or live filesystem security audit:
```bash
# Audit an offline mounted partition at /mnt/target
python redboot.py audit full --target /mnt/target -o output/system_audit.json

# Run CIS benchmark compliance check
python redboot.py audit compliance --target /mnt/target
```

### 5.4 Vulnerability Assessment (`vuln`)
Correlate network scan findings with known CVEs:
```bash
# Scan reconnaissance output for vulnerabilities
python redboot.py vuln scan -i output/recon.json -o output/vuln_report.json
```

### 5.5 Anonymity & Anti-Forensics (`anonymity`)
Audit anonymity posture, routing, and DNS leaks:
```bash
# Inspect Tor routing and DNS leak posture
python redboot.py anonymity audit

# Randomize MAC address on lab interface
python redboot.py anonymity mac-randomize --interface eth0
```

### 5.6 Digital Forensics (`forensics`)
Perform bit-stream imaging, carving, and timeline generation:
```bash
# Acquire forensic image of target partition
python redboot.py forensics image --source /dev/sdb1 --dest output/target_image.raw --case-id CASE-001

# Carve deleted files from raw disk image
python redboot.py forensics carve --image output/target_image.raw --out-dir output/carved_files/

# Generate timeline of disk activity
python redboot.py forensics timeline --target /mnt/target -o output/timeline.csv
```

### 5.7 Evidence Vault & Chain of Custody (`evidence`)
Ingest digital artifacts into the tamper-evident vault and verify ledger integrity:
```bash
# Ingest an artifact into the vault
python redboot.py evidence collect -f output/target_image.raw -d "Raw forensic disk dump" -c "analyst-01"

# Verify cryptographic integrity of all vaulted evidence and ledger
python redboot.py evidence verify --vault-dir output/evidence_vault/
```

### 5.8 Report Generation (`report`)
Consolidate all stage outputs into client-ready reports:
```bash
# Generate HTML, Markdown, and JSON deliverables
python redboot.py report generate -d output/ --case-id CASE-2026-001 --title "Endpoint Security Audit"
```

---

## 6. Setting Up the Docker Simulation Lab

For isolated testing without secondary physical hardware, use the Docker multi-container laboratory:

### 6.1 Starting the Lab Environment
```bash
cd lab/docker/
docker compose up -d
```
This initializes 4 isolated containers on the `192.168.56.0/24` bridge network:
- **`web-target` (`192.168.56.10`):** Apache 2.4.49 (CVE-2021-41773 Path Traversal)
- **`db-target` (`192.168.56.20`):** MySQL 5.7 & Redis 6.0 (CVE-2022-0543 Lua Sandbox Escape)
- **`ftp-ssh-target` (`192.168.56.30`):** vsftpd 2.3.4 (CVE-2011-2523 Backdoor) & OpenSSH 7.4p1
- **`forensics-target` (`192.168.56.40`):** Seeded raw disk image and anomalous Linux logs

### 6.2 Checking Container Health
```bash
docker compose ps
```

### 6.3 Tearing Down the Lab
```bash
docker compose down
```

---

## 7. Executing Automated Lab Scenarios

RedBoot includes 5 turnkey automated laboratory scenarios located in `lab/scenarios/`:

```bash
# 1. Basic Reconnaissance
python redboot.py scenario -s lab/scenarios/basic_recon.yaml -o output/scn01/

# 2. Offline System Audit
python redboot.py scenario -s lab/scenarios/system_audit.yaml -o output/scn02/

# 3. Vulnerability Assessment
python redboot.py scenario -s lab/scenarios/vuln_scan.yaml -o output/scn03/

# 4. Forensic Investigation
python redboot.py scenario -s lab/scenarios/forensic_investigation.yaml -o output/scn04/

# 5. Full End-to-End Engagement
python redboot.py scenario -s lab/scenarios/full_engagement.yaml -o output/scn05/
```

### Dry-Run Mode
To validate target scope without sending network packets or modifying files:
```bash
python redboot.py scenario -s lab/scenarios/basic_recon.yaml --dry-run
```

---

## 8. Verifying Evidence Vault & Chain of Custody

All scenario outputs and ingested artifacts are automatically hashed and recorded in `output/<scenario_dir>/evidence_vault/`:

1. **`vault_manifest.json`:** Contains file metadata, original size, and SHA-256 / SHA-512 cryptographic digests.
2. **`custody.json`:** Append-only ledger linking sequential blocks:
   $$\text{Block Hash}_i = \text{SHA256}(\text{Index}_i \parallel \text{Timestamp}_i \parallel \text{EvidenceID}_i \parallel \text{FileHash}_i \parallel \text{PrevHash}_{i-1})$$

To verify integrity at any time:
```bash
python redboot.py evidence verify --vault-dir output/scn05/evidence_vault/
```

A successful audit produces:
```
=================================================================
  Evidence Vault Verification Report
=================================================================
  Vault Location:            output/scn05/evidence_vault
  Overall Integrity:         VALID (VERIFIED)
  Chain of Custody Status:   VALID (6 blocks intact)
  Artifact Hashes Match:     YES (6/6 files verified)
=================================================================
```

---

## 9. Troubleshooting & FAQ

**Q: ScopeViolation error occurs when scanning a target IP?**  
**A:** RedBoot strictly enforces scope boundaries. Ensure your target IP is listed under `scope.targets` in your scenario YAML or configuration file, and is not within `scope.excluded`.

**Q: The system won't boot from the USB drive?**  
**A:** Check that **Fast Startup** is disabled in Windows power settings, and verify in your UEFI setup that external USB boot is permitted. If Secure Boot rejects the kernel, ensure UEFI CSM or custom certificate enrollment is configured.

**Q: Can I run RedBoot inside a Virtual Machine?**  
**A:** Yes. RedBoot ISO boots directly in VMware Workstation, VirtualBox, or QEMU/KVM. For disk forensics exercises, attach secondary virtual disks (`.vdi` or `.vmdk`) as raw storage.
