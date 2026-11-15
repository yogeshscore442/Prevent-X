"""
PREVENT-X Multi-Layer Payload Normalizer
Safely decodes nested evasion techniques including URL, double URL, HTML entities,
Unicode, Hex, and JSON escapes, with controlled Base64 inspection and strict recursion limits.
Preserves original raw evidence and prevents decompression/recursion bomb attacks.
"""

import base64
import html
import json
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple

logger = logging.getLogger("preventx.network_defense.normalization")

MAX_SAFE_PAYLOAD_LENGTH = 65536
MAX_RECURSION_DEPTH = 4
MAX_BASE64_INSPECT_BYTES = 1024

UNICODE_PATTERN = re.compile(r"\\u([0-9a-fA-F]{4})")
HEX_PATTERN = re.compile(r"\\x([0-9a-fA-F]{2})")
BASE64_CANDIDATE_PATTERN = re.compile(r"([A-Za-z0-9+/]{16,}={0,2})")

SUSPICIOUS_TOKENS = {
    "select", "union", "insert", "update", "delete", "drop",
    "<script", "javascript:", "onload=", "onerror=",
    "../", "..\\", "etc/passwd", "win.ini", "cmd.exe",
    "powershell", "whoami", "curl", "wget", "eval(", "exec(",
    "${", "#{", "{{", "<!entity", "<!doctype", "ldap://", "gopher://"
}


@dataclass
class NormalizedPayload:
    raw_text: str
    normalized_text: str
    obfuscation_detected: bool
    detected_techniques: List[str] = field(default_factory=list)
    extracted_base64_fragments: List[str] = field(default_factory=list)


class PayloadNormalizer:
    """
    Enterprise-grade payload canonicalizer with protection against recursive bombs.
    """

    def __init__(
        self,
        max_depth: int = MAX_RECURSION_DEPTH,
        max_length: int = MAX_SAFE_PAYLOAD_LENGTH,
    ):
        self.max_depth = max_depth
        self.max_length = max_length

    def normalize(self, raw_payload: str) -> NormalizedPayload:
        if not raw_payload or not isinstance(raw_payload, str):
            return NormalizedPayload(
                raw_text="",
                normalized_text="",
                obfuscation_detected=False,
            )

        # Enforce size bounds against decompression bomb attacks
        truncated_raw = raw_payload[: self.max_length]
        current_text = truncated_raw
        techniques: List[str] = []
        base64_fragments: List[str] = []

        for depth in range(self.max_depth):
            previous_text = current_text

            # 1. URL / Double URL Decoding
            try:
                decoded_url = urllib.parse.unquote(current_text)
                if decoded_url != current_text:
                    step_name = f"url_decode_pass_{depth + 1}" if depth > 0 else "url_decode"
                    if step_name not in techniques:
                        techniques.append(step_name)
                    current_text = decoded_url
            except Exception:
                pass

            # 2. HTML Entity Unescaping
            try:
                unescaped_html = html.unescape(current_text)
                if unescaped_html != current_text:
                    if "html_entity_unescape" not in techniques:
                        techniques.append("html_entity_unescape")
                    current_text = unescaped_html
            except Exception:
                pass

            # 3. Unicode Escapes (e.g. \u0027 -> ')
            if "\\u" in current_text or "\\U" in current_text:
                try:
                    decoded_unicode = UNICODE_PATTERN.sub(
                        lambda m: chr(int(m.group(1), 16)), current_text
                    )
                    if decoded_unicode != current_text:
                        if "unicode_unescape" not in techniques:
                            techniques.append("unicode_unescape")
                        current_text = decoded_unicode
                except Exception:
                    pass

            # 4. Hex Escapes (e.g. \x27 -> ')
            if "\\x" in current_text or "\\X" in current_text:
                try:
                    decoded_hex = HEX_PATTERN.sub(
                        lambda m: chr(int(m.group(1), 16)), current_text
                    )
                    if decoded_hex != current_text:
                        if "hex_unescape" not in techniques:
                            techniques.append("hex_unescape")
                        current_text = decoded_hex
                except Exception:
                    pass

            # 5. JSON String Escape Decoding (e.g. \", \/, \\, \n)
            if any(escape in current_text for escape in ['\\"', '\\/', '\\\\', '\\n', '\\t', '\\r']):
                try:
                    # Wrap in JSON string and decode
                    wrapped = f'"{current_text}"'
                    decoded_json = json.loads(wrapped)
                    if decoded_json != current_text:
                        if "json_escape_unescape" not in techniques:
                            techniques.append("json_escape_unescape")
                        current_text = decoded_json
                except Exception:
                    # Fallback manual unescape for common escapes
                    manual = current_text.replace('\\"', '"').replace('\\/', '/').replace('\\\\', '\\')
                    if manual != current_text:
                        if "json_escape_unescape" not in techniques:
                            techniques.append("json_escape_unescape")
                        current_text = manual

            # Check if convergence reached (no further change in this pass)
            if current_text == previous_text:
                break

        # 6. Controlled Base64 Inspection (WITHOUT modifying raw or canonical text)
        for match in BASE64_CANDIDATE_PATTERN.finditer(current_text):
            candidate = match.group(1)[:MAX_BASE64_INSPECT_BYTES]
            # Ensure valid padding
            padded = candidate + "=" * (-len(candidate) % 4)
            try:
                decoded_bytes = base64.b64decode(padded, validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore").strip()
                if decoded_str and any(t in decoded_str.lower() for t in SUSPICIOUS_TOKENS):
                    if "base64_embedded_payload" not in techniques:
                        techniques.append("base64_embedded_payload")
                    base64_fragments.append(decoded_str[:256])
            except Exception:
                pass

        obfuscation_detected = len(techniques) > 0 or len(base64_fragments) > 0

        return NormalizedPayload(
            raw_text=truncated_raw,
            normalized_text=current_text,
            obfuscation_detected=obfuscation_detected,
            detected_techniques=techniques,
            extracted_base64_fragments=base64_fragments,
        )


# Global normalizer instance
payload_normalizer = PayloadNormalizer()
