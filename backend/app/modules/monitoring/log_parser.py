"""
PREVENT-X Nginx Log Parsing Engine (MOD-09)
Safely parses standard combined access logs, Nginx JSON logs, and error logs into
normalized SecurityEvent data structures.
"""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.app.modules.monitoring.sanitizer import sanitize_payload, sanitize_string

logger = logging.getLogger("preventx.monitoring.log_parser")

# Standard Nginx combined access log regex
# Example: 192.168.1.50 - - [15/Nov/2026:14:15:32 +0000] "GET /download?file=../../etc/passwd HTTP/1.1" 403 162 "-" "curl/7.68.0"
COMBINED_LOG_REGEX = re.compile(
    r'^(?P<remote_addr>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<auth_user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<body_bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)")?'
    r'(?:\s+"(?P<user_agent>[^"]*)")?'
)

# Nginx error log regex
# Example: 2026/11/15 14:15:30 [error] 1234#0: *12 directory index forbidden, client: 192.168.1.100, server: localhost, request: "GET / HTTP/1.1"
ERROR_LOG_REGEX = re.compile(
    r'^(?P<time>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'\[(?P<level>\w+)\]\s+'
    r'\d+#\d+:\s+'
    r'(?P<message>.*?)(?:,\s+client:\s+(?P<client>[^,]+))?(?:,\s+server:\s+(?P<server>[^,]+))?(?:,\s+request:\s+"(?P<request>[^"]*)")?'
)


def parse_nginx_access_timestamp(ts_str: str) -> datetime:
    """
    Parses Nginx standard timestamp format (e.g. '15/Nov/2026:14:15:32 +0000') into UTC datetime.
    """
    try:
        # Format: 15/Nov/2026:14:15:32 +0000
        dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def parse_request_line(request_line: str) -> Tuple[str, str, str]:
    """
    Splits 'METHOD /uri HTTP/version' safely into (method, uri, protocol).
    """
    if not request_line or request_line == "-":
        return "UNKNOWN", "/", "HTTP/1.1"
    parts = request_line.strip().split()
    if len(parts) >= 3:
        return sanitize_string(parts[0], 16), sanitize_string(parts[1], 1024), sanitize_string(parts[2], 16)
    elif len(parts) == 2:
        return sanitize_string(parts[0], 16), sanitize_string(parts[1], 1024), "HTTP/1.1"
    elif len(parts) == 1:
        return "UNKNOWN", sanitize_string(parts[0], 1024), "HTTP/1.1"
    return "UNKNOWN", "/", "HTTP/1.1"


class NginxLogParser:
    """
    Robust, fault-tolerant parser for Nginx access, error, and JSON logs.
    """

    @classmethod
    def parse_line(cls, line: str) -> Optional[Dict[str, Any]]:
        return cls.parse_log_line(line)

    @classmethod
    def parse_log_line(cls, line: str) -> Optional[Dict[str, Any]]:
        """
        Parses a single line of Nginx log into a normalized event dictionary.
        Returns None if line is empty or cannot be parsed.
        """
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        # 1. Try parsing as JSON first
        if line.startswith("{") and line.endswith("}"):
            try:
                data = json.loads(line)
                return cls._parse_json_log(data, line)
            except Exception:
                pass

        # 2. Try parsing as standard Combined Access Log
        match = COMBINED_LOG_REGEX.match(line)
        if match:
            return cls._parse_combined_match(match, line)

        # 3. Try parsing as Nginx Error Log
        err_match = ERROR_LOG_REGEX.match(line)
        if err_match:
            return cls._parse_error_match(err_match, line)

        return None

    @classmethod
    def _parse_combined_match(cls, match: re.Match, raw_line: str) -> Dict[str, Any]:
        groups = match.groupdict()
        remote_addr = sanitize_string(groups.get("remote_addr"), 64)
        raw_time = groups.get("time") or ""
        dt = parse_nginx_access_timestamp(raw_time)
        request_line = groups.get("request") or ""
        method, uri, proto = parse_request_line(request_line)
        status_code = int(groups.get("status") or 0)
        user_agent = sanitize_string(groups.get("user_agent") or "-", 512)

        # Severity & category determination
        severity, category, title = cls._classify_traffic(status_code, uri, method, user_agent)

        return {
            "source": "NGINX",
            "category": category,
            "severity": severity,
            "confidence": 1.0,
            "title": title,
            "description": f"Nginx {method} {uri} responded with HTTP {status_code} to {remote_addr}",
            "source_ip": remote_addr,
            "target_uri": uri,
            "http_method": method,
            "status_code": status_code,
            "timestamp": dt,
            "raw_payload": sanitize_payload(raw_line),
            "event_metadata": {
                "user_agent": user_agent,
                "protocol": proto,
                "ident": groups.get("ident"),
                "auth_user": groups.get("auth_user"),
                "body_bytes": groups.get("body_bytes"),
                "referer": sanitize_string(groups.get("referer") or "-", 512),
            },
        }

    @classmethod
    def _parse_json_log(cls, data: Dict[str, Any], raw_line: str) -> Dict[str, Any]:
        remote_addr = sanitize_string(data.get("remote_addr") or data.get("client_ip") or "127.0.0.1", 64)
        status_code = int(data.get("status") or data.get("status_code") or 200)
        method = sanitize_string(data.get("request_method") or data.get("method") or "GET", 16)
        uri = sanitize_string(data.get("request_uri") or data.get("uri") or "/", 1024)
        user_agent = sanitize_string(data.get("http_user_agent") or data.get("user_agent") or "-", 512)

        severity, category, title = cls._classify_traffic(status_code, uri, method, user_agent)

        return {
            "source": "NGINX",
            "category": category,
            "severity": severity,
            "confidence": 1.0,
            "title": title,
            "description": f"Nginx {method} {uri} responded with HTTP {status_code} to {remote_addr}",
            "source_ip": remote_addr,
            "target_uri": uri,
            "http_method": method,
            "status_code": status_code,
            "timestamp": datetime.now(timezone.utc),
            "raw_payload": sanitize_payload(raw_line),
            "event_metadata": data,
        }

    @classmethod
    def _parse_error_match(cls, match: re.Match, raw_line: str) -> Dict[str, Any]:
        groups = match.groupdict()
        client = sanitize_string(groups.get("client") or "127.0.0.1", 64)
        level = (groups.get("level") or "error").lower()
        message = sanitize_string(groups.get("message") or "Nginx internal error", 512)
        request_line = groups.get("request") or ""
        method, uri, _ = parse_request_line(request_line)

        severity = "HIGH" if level in ("crit", "alert", "emerg") else "MEDIUM"

        return {
            "source": "NGINX",
            "category": "SYSTEM",
            "severity": severity,
            "confidence": 1.0,
            "title": f"Nginx Error Log: {level.upper()}",
            "description": f"{message} (client: {client})",
            "source_ip": client,
            "target_uri": uri,
            "http_method": method,
            "status_code": 500,
            "timestamp": datetime.now(timezone.utc),
            "raw_payload": sanitize_payload(raw_line),
            "event_metadata": {"error_level": level, "error_message": message},
        }

    @classmethod
    def _classify_traffic(cls, status_code: int, uri: str, method: str, user_agent: str) -> Tuple[str, str, str]:
        """
        Determines event severity, category, and descriptive title from traffic telemetry.
        """
        uri_lower = uri.lower()
        ua_lower = user_agent.lower()

        # Check for attack patterns in URI
        is_attack_pattern = any(
            pattern in uri_lower
            for pattern in ("union", "select", "script", "../", "..\\", "/etc/passwd", "/etc/shadow", "whoami")
        )

        is_scanner_ua = any(s in ua_lower for s in ("sqlmap", "nikto", "dirbuster", "nmap", "gobuster"))

        if status_code == 403:
            if is_attack_pattern or is_scanner_ua:
                return "HIGH", "SECURITY", "WAF Blocked Web Application Attack"
            return "MEDIUM", "SECURITY", "Nginx 403 Forbidden Access Denied"
        elif status_code == 405:
            return "MEDIUM", "SECURITY", f"Restricted HTTP Method Blocked ({method})"
        elif status_code >= 500:
            return "MEDIUM", "SYSTEM", f"Upstream Application Error (HTTP {status_code})"
        elif status_code == 404:
            if is_attack_pattern:
                return "MEDIUM", "SECURITY", "Potential Directory Traversal Probe (404)"
            return "INFO", "SECURITY", "Resource Not Found (404)"
        elif status_code == 401:
            return "LOW", "AUDIT", "Unauthorized Access Attempt (401)"
        else:
            return "INFO", "SECURITY", f"Nginx Ingress Request ({status_code} OK)"
