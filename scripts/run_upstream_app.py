"""
PREVENT-X Local Upstream Target Application (Simulated SMB Business Backend)
Listens on 127.0.0.1:8086 to simulate an upstream web application protected by
the PREVENT-X Nginx Virtual Patching reverse proxy.
"""

import argparse
from datetime import datetime, timezone
import http.server
import json
import logging
import os
from pathlib import Path
import sys
from typing import Tuple

# Ensure logs directory exists
LOGS_DIR = Path(__file__).resolve().parent.parent / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "upstream_app.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(str(LOG_FILE), encoding="utf-8"),
    ],
)
logger = logging.getLogger("preventx.upstream_app")


class UpstreamRequestHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP handler serving simulated business endpoints for reverse proxy testing.
    """
    server_version = "PreventX-Upstream/1.0.0"

    def _send_json_response(self, status_code: int, data: dict, custom_headers: dict = None):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Upstream-Backend", "PreventX-Mock-App")
        self.send_header("X-Upstream-Service", "SecurePay-Backend")
        if custom_headers:
            for k, v in custom_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        logger.info("%s - %s", self.client_address[0], format % args)

    def do_GET(self):
        # Health check endpoint
        if self.path in ("/health", "/api/v1/health"):
            self._send_json_response(200, {
                "status": "HEALTHY",
                "service": "PREVENT-X Upstream Target Application",
                "port": self.server.server_port,
                "host": self.server.server_address[0],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return

        # Checkout test endpoint (used in security validation and E2E workflow tests)
        if self.path.startswith("/api/v1/checkout"):
            self._send_json_response(200, {
                "status": "PROCESSED",
                "service": "SecurePay-Backend",
                "path": self.path,
                "message": "Payment processing business logic executed safely.",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return

        # General legitimate traffic endpoint
        self._send_json_response(200, {
            "status": "UPSTREAM_OK",
            "service": "PREVENT-X Upstream Target Application",
            "path": self.path,
            "method": "GET",
            "message": "Legitimate business traffic processed successfully.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_length) if content_length > 0 else b""
        
        self._send_json_response(200, {
            "status": "PROCESSED",
            "service": "SecurePay-Backend",
            "path": self.path,
            "method": "POST",
            "bytes_received": len(post_body),
            "message": "Payment processing business logic executed safely.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def do_PUT(self):
        self._send_json_response(200, {
            "status": "UPSTREAM_OK",
            "method": "PUT",
            "path": self.path,
            "message": "Resource updated successfully.",
        })

    def do_DELETE(self):
        self._send_json_response(200, {
            "status": "UPSTREAM_OK",
            "method": "DELETE",
            "path": self.path,
            "message": "Resource removed successfully.",
        })

    def do_OPTIONS(self):
        self._send_json_response(200, {
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"],
            "allow_cors": True,
        }, custom_headers={
            "Allow": "GET, POST, PUT, DELETE, OPTIONS, HEAD",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, HEAD",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
        })

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Upstream-Backend", "PreventX-Mock-App")
        self.end_headers()


def run(host: str = "127.0.0.1", port: int = 8086):
    server_address: Tuple[str, int] = (host, port)
    
    # Save PID to logs
    pid_file = LOGS_DIR / "upstream.pid"
    pid_file.write_text(str(os.getpid()), encoding="utf-8")
    
    server = http.server.ThreadingHTTPServer(server_address, UpstreamRequestHandler)
    server.allow_reuse_address = True
    
    logger.info("==============================================================================")
    logger.info("  PREVENT-X Upstream Target Application (Mock SMB Payment Backend)")
    logger.info("  Listening on: http://%s:%d (Loopback Bound)", host, port)
    logger.info("  PID: %d | Log: %s", os.getpid(), LOG_FILE)
    logger.info("==============================================================================")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down upstream test application...")
    finally:
        server.server_close()
        if pid_file.exists():
            try:
                pid_file.unlink()
            except Exception:
                pass
        logger.info("Upstream test application stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PREVENT-X Upstream Test Application")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8086, help="Bind port (default: 8086)")
    args = parser.parse_args()
    run(host=args.host, port=args.port)
