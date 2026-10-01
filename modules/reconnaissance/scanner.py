"""
RedBoot Reconnaissance Scanner

Provides network host discovery, port scanning, service banner grabbing,
and structured scan result generation. Strictly enforces authorized scope.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
from datetime import datetime, timezone
from typing import Any

from modules.core.logger import get_logger
from modules.core.scope import ScopeValidator, ScopeViolation

COMMON_PORTS = [
    21,  # FTP
    22,  # SSH
    23,  # Telnet
    25,  # SMTP
    53,  # DNS
    80,  # HTTP
    110,  # POP3
    111,  # RPC
    135,  # MSRPC
    139,  # NetBIOS
    143,  # IMAP
    443,  # HTTPS
    445,  # SMB
    993,  # IMAPS
    995,  # POP3S
    1433,  # MSSQL
    1521,  # Oracle
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8000,  # HTTP Alt
    8080,  # HTTP Proxy/Dev
    8443,  # HTTPS Alt
    9000,  # SonarQube / PHP-FPM
    27017,  # MongoDB
]

SERVICE_PROBES: dict[int, bytes] = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
    21: b"",
    22: b"",
    25: b"EHLO redboot.lab\r\n",
}

PORT_SERVICES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    9000: "http-service",
    27017: "mongodb",
}


class ReconScanner:
    """
    Scope-enforced reconnaissance scanner.
    """

    def __init__(
        self, validator: ScopeValidator, timeout: float = 0.5, max_workers: int = 50
    ) -> None:
        self.validator = validator
        self.timeout = timeout
        self.max_workers = max_workers
        self.logger = get_logger("recon-scanner")

    def grab_banner(self, ip: str, port: int) -> str:
        """Attempt to grab a service banner from an open port."""
        banner = ""
        probe = SERVICE_PROBES.get(port, b"")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                if probe:
                    sock.sendall(probe)
                response = sock.recv(1024)
                banner = response.decode("utf-8", errors="ignore").strip()
        except Exception:
            pass
        return banner

    def check_port(self, ip: str, port: int) -> dict[str, Any] | None:
        """Scan a single TCP port on target IP."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    service_name = PORT_SERVICES.get(port, "unknown")
                    banner = self.grab_banner(ip, port)
                    return {
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "service": service_name,
                        "banner": banner,
                    }
        except Exception:
            pass
        return None

    def scan_host(self, target: str, ports: list[int] | None = None) -> dict[str, Any]:
        """
        Scan a single host for open ports and services.
        Validates target against authorized scope before executing.
        """
        self.validator.validate(target)

        target_ports = ports if ports is not None else COMMON_PORTS
        self.logger.info(
            f"Starting reconnaissance scan on {target} ({len(target_ports)} ports)"
        )

        # Resolve hostname to IP if needed
        try:
            target_ip = socket.gethostbyname(target)
        except socket.error:
            target_ip = target

        open_ports: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:
            future_to_port = {
                executor.submit(self.check_port, target_ip, port): port
                for port in target_ports
            }
            for future in concurrent.futures.as_completed(future_to_port):
                res = future.result()
                if res:
                    open_ports.append(res)

        open_ports.sort(key=lambda x: x["port"])

        return {
            "target": target,
            "ip": target_ip,
            "status": "up" if open_ports else "filtered_or_down",
            "ports_scanned": len(target_ports),
            "open_ports_count": len(open_ports),
            "findings": open_ports,
        }

    def scan_range(
        self, cidr_or_target: str, ports: list[int] | None = None
    ) -> dict[str, Any]:
        """
        Scan a network CIDR range or single target.
        Enforces scope validation for every host in range.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        try:
            net = ipaddress.ip_network(cidr_or_target, strict=False)
            hosts = [str(h) for h in net.hosts()]
            if not hosts:
                hosts = [str(net.network_address)]
        except ValueError:
            hosts = [cidr_or_target]

        # Safety: restrict single scan batch to 256 hosts maximum
        if len(hosts) > 256:
            raise ValueError(
                f"Range too large ({len(hosts)} hosts). Maximum supported batch is 256 hosts."
            )

        valid_hosts: list[str] = []
        for host in hosts:
            try:
                self.validator.validate(host)
                valid_hosts.append(host)
            except ScopeViolation:
                self.logger.warning(f"Skipping host outside authorized scope: {host}")

        results: list[dict[str, Any]] = []
        for host in valid_hosts:
            host_res = self.scan_host(host, ports=ports)
            if host_res["open_ports_count"] > 0:
                results.append(host_res)

        return {
            "module": "reconnaissance",
            "timestamp": timestamp,
            "scope": cidr_or_target,
            "scanned_hosts_count": len(valid_hosts),
            "active_hosts_count": len(results),
            "findings": results,
            "metadata": {
                "scan_type": "tcp_syn_connect",
                "default_ports_count": len(ports if ports else COMMON_PORTS),
            },
        }
