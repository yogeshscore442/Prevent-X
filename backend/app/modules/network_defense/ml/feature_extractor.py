"""
PREVENT-X ML Feature Extractor
Extracts 16 statistical, structural, and semantic features from raw HTTP requests
for machine learning classification and anomaly detection.
"""

import collections
import math
import re
from typing import Any, Dict, List, Optional, Tuple

FEATURE_NAMES: List[str] = [
    "threat_signal_count",
    "sqli_keyword_count",
    "xss_token_count",
    "traversal_token_count",
    "rce_token_count",
    "special_char_ratio",
    "shannon_entropy",
    "hex_encoding_ratio",
    "digit_ratio",
    "uppercase_ratio",
    "url_length",
    "path_depth",
    "query_length",
    "query_param_count",
    "body_length",
    "content_type_is_json",
]

SPECIAL_CHARS = set("<>'\"/;{}$`|&()[]\\^~!-=+*%@#")
HEX_ENCODED_REGEX = re.compile(r"%[0-9a-fA-F]{2}")
SQLI_KEYWORDS = re.compile(r"(?i)\b(select|union|drop|from|where|insert|delete|update|exec)\b")
XSS_TOKENS = re.compile(r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|eval\(|alert\()")
TRAVERSAL_TOKENS = re.compile(r"(?i)(\.\./|\.\.\\|%2e%2e)")
RCE_TOKENS = re.compile(r"(?i)\b(bash|sh|cmd|powershell|whoami|curl|wget|system|runtime\.getruntime)\b")


class FeatureExtractor:
    """Computes fixed-length numerical feature vectors from HTTP request attributes."""

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """Calculates Shannon entropy H = -sum(p * log2(p)) for text characters."""
        if not text:
            return 0.0
        counts = collections.Counter(text)
        total = len(text)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    def extract_features(
        self,
        method: str,
        path: str,
        query: Optional[str] = None,
        body: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[float]:
        """
        Extracts 16 numerical features as a list of floats.
        """
        p = path or "/"
        q = query or ""
        b = body or ""
        hdrs = {k.lower(): v for k, v in (headers or {}).items()}

        combined_payload = f"{q} {b}".strip()
        total_len = len(combined_payload) if combined_payload else 1

        # 1. url_length
        url_len = float(len(p) + len(q))

        # 2. path_depth
        path_depth = float(p.count("/"))

        # 3. query_length
        q_len = float(len(q))

        # 4. query_param_count
        param_count = float(q.count("&") + (1 if q and "=" in q else 0))

        # 5. body_length
        body_len = float(len(b))

        # 6. shannon_entropy
        entropy = self.calculate_shannon_entropy(combined_payload)

        # 7. special_char_ratio
        special_count = sum(1 for ch in combined_payload if ch in SPECIAL_CHARS)
        special_ratio = round(special_count / total_len, 4) if total_len > 1 else 0.0

        # 8. digit_ratio
        digit_count = sum(1 for ch in combined_payload if ch.isdigit())
        digit_ratio = round(digit_count / total_len, 4) if total_len > 1 else 0.0

        # 9. uppercase_ratio
        upper_count = sum(1 for ch in combined_payload if ch.isupper())
        upper_ratio = round(upper_count / total_len, 4) if total_len > 1 else 0.0

        # 10. sqli_keyword_count
        sqli_count = float(len(SQLI_KEYWORDS.findall(combined_payload)))

        # 11. xss_token_count
        xss_count = float(len(XSS_TOKENS.findall(combined_payload)))

        # 12. traversal_token_count
        traversal_count = float(len(TRAVERSAL_TOKENS.findall(f"{p} {q} {b}")))

        # 13. rce_token_count
        rce_count = float(len(RCE_TOKENS.findall(combined_payload)))

        # 14. hex_encoding_ratio
        hex_matches = len(HEX_ENCODED_REGEX.findall(f"{p} {q} {b}"))
        hex_ratio = round(hex_matches / (len(p) + total_len), 4)

        # 15. content_type_is_json
        ct = hdrs.get("content-type", "")
        is_json = 1.0 if "application/json" in ct.lower() else 0.0

        # 16. threat_signal_count (composite high-priority signal)
        threat_signal = float(sqli_count + xss_count + traversal_count + rce_count)

        return [
            threat_signal,
            sqli_count,
            xss_count,
            traversal_count,
            rce_count,
            special_ratio,
            entropy,
            hex_ratio,
            digit_ratio,
            upper_ratio,
            url_len,
            path_depth,
            q_len,
            param_count,
            body_len,
            is_json,
        ]


feature_extractor = FeatureExtractor()
