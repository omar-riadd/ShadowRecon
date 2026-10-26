"""Lightweight in-memory mock HTTP vulnerable target server for integration testing."""
from __future__ import annotations

import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional


class MockTargetRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler simulating target endpoints, WAF blocking, and reflected parameters."""

    def log_message(self, format: str, *args) -> None:
        """Suppress standard HTTP server request logs to keep test output clean."""
        pass

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)

        # 1. WAF active probe evaluation
        if "__shadowrecon_probe" in parsed.query or any("__shadowrecon_probe" in k for k in query):
            # Check for bypass headers
            xff = self.headers.get("X-Forwarded-For", "")
            ua = self.headers.get("User-Agent", "")
            if xff == "127.0.0.1" or "Googlebot" in ua:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "bypassed", "msg": "WAF bypass confirmed"}')
                return
            else:
                self.send_response(403)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body><h1>403 Forbidden: Blocked by Mock WAF</h1></body></html>")
                return

        # 2. Reflected XSS search endpoint
        if parsed.path == "/search":
            q_param = query.get("q", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            body = f"<html><body><h1>Search Results</h1><p>Query: {q_param}</p></body></html>"
            self.wfile.write(body.encode("utf-8"))
            return

        # 3. SQLi API endpoint
        if parsed.path == "/api":
            id_param = query.get("id", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if "'" in id_param or "1=1" in id_param:
                self.wfile.write(b'{"error": "syntax error in SQL statement near ' + id_param.encode("utf-8") + b'"}')
            else:
                self.wfile.write(b'{"status": "ok", "id": "' + id_param.encode("utf-8") + b'"}')
            return

        # 4. Root & standard paths
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        html_doc = """<!DOCTYPE html>
<html>
<head><title>Mock Vulnerable Target</title></head>
<body>
    <h1>Mock Application</h1>
    <a href="/search?q=recon">Search</a>
    <a href="/api?id=10">API Endpoint</a>
    <a href="/admin/login">Admin</a>
</body>
</html>"""
        self.wfile.write(html_doc.encode("utf-8"))

    def do_HEAD(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Allow", "GET, HEAD, OPTIONS, POST")
        self.end_headers()

    def do_POST(self) -> None:
        content_len = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_len) if content_len > 0 else b""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "received", "bytes": ' + str(len(post_body)).encode() + b'}')


class MockTargetServer:
    """Threaded HTTP server running on localhost on a free dynamic port."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self.requested_port = port
        self.server: Optional[ThreadingHTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        self.port: int = 0

    def start(self) -> str:
        self.server = ThreadingHTTPServer((self.host, self.requested_port), MockTargetRequestHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self.base_url

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self.thread:
            self.thread.join(timeout=2.0)
            self.thread = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def __enter__(self) -> "MockTargetServer":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()
