"""
PREVENT-X Security Event Sanitization Engine (MOD-09)
Defends against log injection, header tampering, and sensitive credential leakage
by sanitizing authentication tokens, cookies, passwords, and bounded payload strings.
"""

import re
from typing import Any, Dict, Optional, Union

# Sensitive parameter keys to redact
SENSITIVE_PARAM_PATTERNS = [
    re.compile(r"(password|passwd|pwd)[\s=:\"']+([^\s\"'&,;]+)", re.IGNORECASE),
    re.compile(r"(token|access_token|refresh_token|bearer)[\s=:\"']+([^\s\"'&,;]+)", re.IGNORECASE),
    re.compile(r"(secret|api_key|apikey|private_key)[\s=:\"']+([^\s\"'&,;]+)", re.IGNORECASE),
    re.compile(r"(authorization|cookie|set-cookie)[\s=:\"']+([^\s\"'&,;]+)", re.IGNORECASE),
]

SENSITIVE_HEADER_KEYS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-preventx-token",
}

MAX_FIELD_LENGTH = 1024
MAX_RAW_PAYLOAD_BYTES = 65536  # 64 KB


def sanitize_string(val: Optional[str], max_length: int = MAX_FIELD_LENGTH, strip_crlf: bool = True) -> str:
    """
    Sanitizes single string fields: strips CRLF to prevent log injection and bounds size.
    """
    if not val:
        return ""
    cleaned = str(val)
    if strip_crlf:
        cleaned = cleaned.replace("\r", " ").replace("\n", " ").strip()
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length] + " [TRUNCATED]"
    return cleaned


def sanitize_headers(headers: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """
    Redacts sensitive authorization and session tokens from HTTP headers.
    """
    if not headers or not isinstance(headers, dict):
        return {}
    sanitized = {}
    for k, v in headers.items():
        clean_key = sanitize_string(str(k), max_length=128)
        if clean_key.lower() in SENSITIVE_HEADER_KEYS:
            sanitized[clean_key] = "[REDACTED]"
        else:
            sanitized[clean_key] = sanitize_string(str(v), max_length=512)
    return sanitized


def sanitize_payload(payload: Optional[Union[str, Dict[str, Any]]]) -> str:
    """
    Sanitizes request bodies or raw payloads: redacts passwords/tokens and enforces bounds.
    """
    if not payload:
        return ""
    if isinstance(payload, dict):
        import json
        try:
            payload_str = json.dumps(payload)
        except Exception:
            payload_str = str(payload)
    else:
        payload_str = str(payload)

    # Redact sensitive patterns
    sanitized = payload_str
    for pat in SENSITIVE_PARAM_PATTERNS:
        sanitized = pat.sub(r"\1=[REDACTED]", sanitized)

    # Enforce 64KB bound
    if len(sanitized.encode("utf-8")) > MAX_RAW_PAYLOAD_BYTES:
        sanitized = sanitized[:MAX_RAW_PAYLOAD_BYTES] + "\n[TRUNCATED: Exceeded 64KB payload limit]"

    return sanitized
