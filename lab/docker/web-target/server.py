"""
RedBoot Lab Web Target Service

Simulates an Apache/2.4.49 web server with mock vulnerable endpoints.
Used exclusively in authorized, isolated laboratory environments.
"""

import http.server
import socketserver

PORT = 80
SSL_PORT = 443
SERVER_BANNER = "Apache/2.4.49 (Unix) OpenSSL/1.1.1l"


class VulnerableHTTPHandler(http.server.SimpleHTTPRequestHandler):
    server_version = SERVER_BANNER
    sys_version = ""

    def do_GET(self):
        # Simulate Apache 2.4.49 path traversal test endpoint
        if "/icons/" in self.path or "/cgi-bin/" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(
                b"[REDBOOT LAB TARGET] Apache 2.4.49 Simulated Endpoint Active.\n"
            )
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        html_content = (
            "<!DOCTYPE html><html><head><title>RedBoot Target Web Application</title></head>"
            "<body style='font-family:sans-serif;background:#1a1a1a;color:#eee;padding:40px;'>"
            "<h1>RedBoot Academic Vulnerable Target</h1>"
            "<p>Host: <code>web-target.lab.local (192.168.56.10)</code></p>"
            "<p>Server: <code>Apache/2.4.49 (Unix)</code></p>"
            "<p>This service simulates an unpatched Apache server for academic vulnerability scanning.</p>"
            "</body></html>"
        )
        self.wfile.write(html_content.encode("utf-8"))

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Server", SERVER_BANNER)
        self.send_header("Content-Type", "text/html")
        self.end_headers()


def run_http():
    with socketserver.TCPServer(("", PORT), VulnerableHTTPHandler) as httpd:
        print(f"[*] Web target HTTP listening on port {PORT}...")
        httpd.serve_forever()


if __name__ == "__main__":
    run_http()
