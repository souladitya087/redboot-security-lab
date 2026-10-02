"""
RedBoot Lab Database Target Service

Simulates MySQL (port 3306) and Redis (port 6379) responses for network scanning.
"""

import socket
import threading

MYSQL_PORT = 3306
REDIS_PORT = 6379


def run_mysql_listener():
    # Simulated MySQL 5.7 handshake packet banner
    handshake_packet = (
        b"\x4a\x00\x00\x00\x0a"
        b"5.7.33-0ubuntu0.18.04.1\x00"
        b"\x01\x00\x00\x00"
        b"abcdefgh\x00"
        b"\xff\xf7\x08\x02\x00\x7f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"ijklmnopqrst\x00"
        b"mysql_native_password\x00"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", MYSQL_PORT))
    sock.listen(5)
    print(f"[*] DB Target: MySQL simulated listener on port {MYSQL_PORT}...")

    while True:
        client, addr = sock.accept()
        try:
            client.sendall(handshake_packet)
        except Exception:
            pass
        finally:
            client.close()


def run_redis_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", REDIS_PORT))
    sock.listen(5)
    print(f"[*] DB Target: Redis simulated listener on port {REDIS_PORT}...")

    while True:
        client, addr = sock.accept()
        try:
            req = client.recv(1024)
            if b"PING" in req:
                client.sendall(b"+PONG\r\n")
            elif b"INFO" in req:
                client.sendall(
                    b"$45\r\n# Server\r\nredis_version:6.0.9\r\nos:Linux\r\n\r\n"
                )
            else:
                client.sendall(b"-NOAUTH Authentication required.\r\n")
        except Exception:
            pass
        finally:
            client.close()


if __name__ == "__main__":
    t_mysql = threading.Thread(target=run_mysql_listener, daemon=True)
    t_redis = threading.Thread(target=run_redis_listener, daemon=True)
    t_mysql.start()
    t_redis.start()
    t_mysql.join()
    t_redis.join()
