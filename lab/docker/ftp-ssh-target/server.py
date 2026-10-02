"""
RedBoot Lab FTP & SSH Target Service

Simulates vsFTPd 2.3.4 (backdoor banner), OpenSSH 7.4p1, and Telnet for
academic security scanning.
"""

import socket
import threading

FTP_PORT = 21
SSH_PORT = 22
TELNET_PORT = 23


def run_ftp_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", FTP_PORT))
    sock.listen(5)
    print(f"[*] FTP listener running on port {FTP_PORT}...")
    while True:
        client, _ = sock.accept()
        try:
            client.sendall(b"220 (vsFTPd 2.3.4)\r\n")
            client.recv(1024)
            client.sendall(b"331 Please specify the password.\r\n")
        except Exception:
            pass
        finally:
            client.close()


def run_ssh_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", SSH_PORT))
    sock.listen(5)
    print(f"[*] SSH listener running on port {SSH_PORT}...")
    while True:
        client, _ = sock.accept()
        try:
            client.sendall(b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n")
        except Exception:
            pass
        finally:
            client.close()


def run_telnet_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", TELNET_PORT))
    sock.listen(5)
    print(f"[*] Telnet listener running on port {TELNET_PORT}...")
    while True:
        client, _ = sock.accept()
        try:
            client.sendall(b"\r\nRedBoot Lab Target Linux System\r\nlogin: ")
        except Exception:
            pass
        finally:
            client.close()


if __name__ == "__main__":
    t_ftp = threading.Thread(target=run_ftp_listener, daemon=True)
    t_ssh = threading.Thread(target=run_ssh_listener, daemon=True)
    t_tel = threading.Thread(target=run_telnet_listener, daemon=True)
    t_ftp.start()
    t_ssh.start()
    t_tel.start()
    t_ftp.join()
    t_ssh.join()
    t_tel.join()
