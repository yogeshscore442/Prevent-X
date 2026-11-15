"""
PREVENT-X Advanced Attack Detection Engine
Specialized multi-category deep inspection engine covering:
1. SSRF (Server-Side Request Forgery)
2. XXE (XML External Entity Injection)
3. SSTI (Server-Side Template Injection)
4. NoSQL Injection
5. LDAP Injection
6. Open Redirect
7. HTTP Request Smuggling
8. GraphQL Abuse & Denial-of-Service
9. Mass Assignment Privilege Escalation
10. JWT Misuse & Algorithm None Exploitation
Avoids duplicating existing SQLi, XSS, Path Traversal, and Command Injection engines.
"""

import base64
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from backend.app.modules.network_defense.normalization.normalizer import (
    NormalizedPayload,
    payload_normalizer,
)

logger = logging.getLogger("preventx.network_defense.detection")

# 1. SSRF Patterns
SSRF_CLOUD_LOOPBACK_REGEX = re.compile(
    r"(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|"
    r"127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]|127\.\d+\.\d+\.\d+|"
    r"0177\.0\.0\.1|0x7f\.0\.0\.1|2130706433|"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3})",
    re.IGNORECASE,
)
SSRF_DANGEROUS_SCHEMES = re.compile(
    r"\b(gopher|file|dict|tftp|ldap|sftp)://", re.IGNORECASE
)
SSRF_PARAM_TRIGGER = re.compile(
    r"(\b(?:url|uri|target|dest|destination|redirect|endpoint|webhook|feed|fetch|src|proxy)\s*=\s*)",
    re.IGNORECASE,
)

# 2. XXE Patterns
XXE_DOCTYPE_ENTITY_REGEX = re.compile(
    r"<!DOCTYPE[^>]+(?:<!ENTITY[^>]+(?:SYSTEM|PUBLIC)[^>]+|SYSTEM\s+[\"'][^\"']+[\"'])",
    re.IGNORECASE | re.DOTALL,
)
XXE_ENTITY_USAGE_REGEX = re.compile(
    r"<!ENTITY\s+[\w\.\-]+\s+(?:SYSTEM|PUBLIC)\s+[\"'](?:file|http|https|ftp|expect)://",
    re.IGNORECASE,
)

# 3. SSTI Patterns
SSTI_REGEX = re.compile(
    r"(\{\{[^}]*(?:config|self|class|mro|subclasses|globals|builtins|import|request|env|eval|exec)[^}]*\}\}|"
    r"\$\{[^}]*(?:java\.lang|Runtime|ProcessBuilder|class\.classLoader|session|application)[^}]*\}|"
    r"#\{[^}]*(?:request|session|context|param)[^}]*\}|"
    r"\{\{\s*7\s*\*\s*7\s*\}\}|\$\{\s*7\s*\*\s*7\s*\}|#\{\s*7\s*\*\s*7\s*\})",
    re.IGNORECASE,
)

# 4. NoSQL Injection Patterns
NOSQL_REGEX = re.compile(
    r"(\$(?:gt|gte|lt|lte|ne|nin|in|regex|where|exists|mod|text|expr|jsonSchema|size)\b|"
    r"\{\s*[\"']\$ne[\"']\s*:\s*(?:null|[\"'][\"']|[0-9]+)\s*\}|"
    r"\{\s*[\"']\$gt[\"']\s*:\s*[\"'][\"']\s*\}|"
    r"\bthis\.[a-zA-Z0-9_]+\s*===?\s*|sleep\s*\(\s*\d+\s*\))",
    re.IGNORECASE,
)

# 5. LDAP Injection Patterns
LDAP_REGEX = re.compile(
    r"(\(\s*[&|!]\s*\([^)]*\)\s*\([^)]*\)\s*\)|"
    r"\*\s*\)\s*\(\s*(?:uid|cn|mail|userPassword|samAccountName)\s*=\s*\*|"
    r"\)\s*\(\s*(?:uid|cn|mail|userPassword)\s*=\s*[\w*]+|"
    r"\(\s*&\s*\([a-zA-Z0-9_-]+=\*\)\s*\([a-zA-Z0-9_-]+=\*\)\))",
    re.IGNORECASE,
)

# 6. Open Redirect Patterns
REDIRECT_REGEX = re.compile(
    r"(?:^|[?&])(?:url|redirect|redirect_to|next|return|return_to|dest|destination|goto|target)\s*=\s*"
    r"(?:https?://(?!(?:localhost|127\.0\.0\.1))[a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,}|//[a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,}|\\\\|javascript:)",
    re.IGNORECASE,
)

# 7. HTTP Request Smuggling Patterns
SMUGGLING_HEADER_REGEX = re.compile(
    r"(\btransfer-encoding\s*:[^\r\n]*chunked[^\r\n]*transfer-encoding|"
    r"\r\n\s*transfer-encoding\s*:|"
    r"transfer-encoding\s*:\s*chunked[\s\S]*content-length\s*:|"
    r"content-length\s*:[^\r\n]*\r\n[^\r\n]*content-length\s*:)",
    re.IGNORECASE,
)

# 8. GraphQL Abuse Patterns
GRAPHQL_INTROSPECTION_REGEX = re.compile(r"(__schema|__type\s*\(|__typename)", re.IGNORECASE)

# 9. Mass Assignment Patterns
MASS_ASSIGNMENT_FIELDS = {
    "role", "is_admin", "is_superuser", "is_staff", "permissions",
    "organization_id", "tenant_id", "credit_balance", "balance",
    "verified", "is_verified", "account_type", "plan_id"
}

# 10. JWT Misuse Patterns
JWT_ALG_NONE_REGEX = re.compile(
    r"\"alg\"\s*:\s*\"none\"", re.IGNORECASE
)


@dataclass
class AttackDetectionResult:
    detected: bool
    category: Optional[str]
    confidence: float
    severity: str
    cwe_id: Optional[str]
    mitre_attack_id: Optional[str]
    explanation: str
    matched_pattern: Optional[str] = None
    obfuscation_detected: bool = False
    detected_techniques: List[str] = None


class AdvancedAttackDetectionEngine:
    """
    Evaluates HTTP requests across 10 independent enterprise attack categories.
    """

    def __init__(self):
        self.normalizer = payload_normalizer

    def inspect_request(
        self,
        method: str,
        path: str,
        query_string: Optional[str] = None,
        body: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> AttackDetectionResult:
        headers = headers or {}
        query = query_string or ""
        body_text = body or ""
        combined_payload = f"{query} {body_text}".strip()

        # Step 1: Payload Normalization to uncover obfuscated threats
        norm_result = self.normalizer.normalize(combined_payload)
        targets_to_inspect = [norm_result.raw_text, norm_result.normalized_text]
        targets_to_inspect.extend(norm_result.extracted_base64_fragments)

        headers_str = "\r\n".join(f"{k}: {v}" for k, v in headers.items())

        # 1. XXE Check (prioritized before URI protocol matching)
        for t in targets_to_inspect:
            if "<" in t and ("doctype" in t.lower() or "entity" in t.lower()):
                xxe_match = XXE_DOCTYPE_ENTITY_REGEX.search(t) or XXE_ENTITY_USAGE_REGEX.search(t)
                if xxe_match:
                    return AttackDetectionResult(
                        detected=True,
                        category="XXE",
                        confidence=96.0,
                        severity="HIGH",
                        cwe_id="CWE-611",
                        mitre_attack_id="T1190",
                        explanation="XML External Entity (XXE) injection declaration detected.",
                        matched_pattern=xxe_match.group(0)[:80],
                        obfuscation_detected=norm_result.obfuscation_detected,
                        detected_techniques=norm_result.detected_techniques,
                    )

        # 2. SSRF Check
        for t in targets_to_inspect:
            scheme_match = SSRF_DANGEROUS_SCHEMES.search(t)
            if scheme_match:
                return AttackDetectionResult(
                    detected=True,
                    category="SSRF",
                    confidence=95.0,
                    severity="HIGH",
                    cwe_id="CWE-918",
                    mitre_attack_id="T1090.003",
                    explanation=f"SSRF attempt: dangerous URI scheme detected ({scheme_match.group(0)}).",
                    matched_pattern=scheme_match.group(0),
                    obfuscation_detected=norm_result.obfuscation_detected,
                    detected_techniques=norm_result.detected_techniques,
                )

            ip_match = SSRF_CLOUD_LOOPBACK_REGEX.search(t)
            if ip_match and (SSRF_PARAM_TRIGGER.search(t) or "://" in t or ip_match.group(0) in ["169.254.169.254", "metadata.google.internal"]):
                return AttackDetectionResult(
                    detected=True,
                    category="SSRF",
                    confidence=92.0,
                    severity="CRITICAL" if "169.254" in ip_match.group(0) else "HIGH",
                    cwe_id="CWE-918",
                    mitre_attack_id="T1552.005",
                    explanation=f"SSRF attempt: unauthorized internal/cloud metadata probe ({ip_match.group(0)}).",
                    matched_pattern=ip_match.group(0),
                    obfuscation_detected=norm_result.obfuscation_detected,
                    detected_techniques=norm_result.detected_techniques,
                )

        # 3. SSTI Check
        for t in targets_to_inspect:
            ssti_match = SSTI_REGEX.search(t)
            if ssti_match:
                return AttackDetectionResult(
                    detected=True,
                    category="SSTI",
                    confidence=94.0,
                    severity="CRITICAL",
                    cwe_id="CWE-1336",
                    mitre_attack_id="T1059",
                    explanation=f"Server-Side Template Injection syntax detected ({ssti_match.group(0)[:60]}).",
                    matched_pattern=ssti_match.group(0),
                    obfuscation_detected=norm_result.obfuscation_detected,
                    detected_techniques=norm_result.detected_techniques,
                )

        # 4. NoSQL Injection Check
        for t in targets_to_inspect:
            nosql_match = NOSQL_REGEX.search(t)
            if nosql_match:
                return AttackDetectionResult(
                    detected=True,
                    category="NOSQL_INJECTION",
                    confidence=90.0,
                    severity="HIGH",
                    cwe_id="CWE-943",
                    mitre_attack_id="T1190",
                    explanation=f"NoSQL operator injection detected ({nosql_match.group(0)}).",
                    matched_pattern=nosql_match.group(0),
                    obfuscation_detected=norm_result.obfuscation_detected,
                    detected_techniques=norm_result.detected_techniques,
                )

        # 5. LDAP Injection Check
        for t in targets_to_inspect:
            ldap_match = LDAP_REGEX.search(t)
            if ldap_match:
                return AttackDetectionResult(
                    detected=True,
                    category="LDAP_INJECTION",
                    confidence=88.0,
                    severity="HIGH",
                    cwe_id="CWE-90",
                    mitre_attack_id="T1078",
                    explanation=f"LDAP filter injection pattern detected ({ldap_match.group(0)}).",
                    matched_pattern=ldap_match.group(0),
                    obfuscation_detected=norm_result.obfuscation_detected,
                    detected_techniques=norm_result.detected_techniques,
                )

        # 6. Open Redirect Check
        for t in [query, norm_result.normalized_text]:
            red_match = REDIRECT_REGEX.search(t)
            if red_match:
                return AttackDetectionResult(
                    detected=True,
                    category="OPEN_REDIRECT",
                    confidence=85.0,
                    severity="MEDIUM",
                    cwe_id="CWE-601",
                    mitre_attack_id="T1566.002",
                    explanation=f"Unvalidated Open Redirect destination detected ({red_match.group(0)}).",
                    matched_pattern=red_match.group(0),
                    obfuscation_detected=norm_result.obfuscation_detected,
                    detected_techniques=norm_result.detected_techniques,
                )

        # 7. HTTP Request Smuggling Check
        smuggle_match = SMUGGLING_HEADER_REGEX.search(headers_str)
        te_hdr = headers.get("transfer-encoding", "").lower()
        cl_hdr = headers.get("content-length", "")
        if smuggle_match or (te_hdr and cl_hdr):
            return AttackDetectionResult(
                detected=True,
                category="HTTP_REQUEST_SMUGGLING",
                confidence=95.0,
                severity="CRITICAL",
                cwe_id="CWE-444",
                mitre_attack_id="T1071.001",
                explanation="HTTP Request Smuggling conflict: dual Content-Length / Transfer-Encoding detected.",
                matched_pattern=te_hdr or "Conflicting CL.TE headers",
                obfuscation_detected=False,
            )

        # 8. GraphQL Abuse Check
        if "/graphql" in path.lower() or "graphql" in path.lower():
            # Check nesting depth
            curly_depth = 0
            max_depth = 0
            for char in body_text:
                if char == "{":
                    curly_depth += 1
                    max_depth = max(max_depth, curly_depth)
                elif char == "}":
                    curly_depth = max(0, curly_depth - 1)

            if max_depth >= 7:
                return AttackDetectionResult(
                    detected=True,
                    category="GRAPHQL_ABUSE",
                    confidence=92.0,
                    severity="HIGH",
                    cwe_id="CWE-400",
                    mitre_attack_id="T1499",
                    explanation=f"GraphQL query nesting depth limit exceeded ({max_depth} levels > threshold 6).",
                    matched_pattern=f"Depth: {max_depth}",
                )

            if GRAPHQL_INTROSPECTION_REGEX.search(body_text):
                return AttackDetectionResult(
                    detected=True,
                    category="GRAPHQL_ABUSE",
                    confidence=80.0,
                    severity="LOW",
                    cwe_id="CWE-200",
                    mitre_attack_id="T1087",
                    explanation="GraphQL schema introspection probe detected in production endpoint.",
                    matched_pattern="__schema",
                )

        # 9. Mass Assignment Check
        if method.upper() in ["POST", "PUT", "PATCH"] and body_text:
            try:
                parsed_json = json.loads(body_text)
                if isinstance(parsed_json, dict):
                    injected_fields = [k for k in parsed_json.keys() if k.lower() in MASS_ASSIGNMENT_FIELDS]
                    if injected_fields:
                        return AttackDetectionResult(
                            detected=True,
                            category="MASS_ASSIGNMENT",
                            confidence=86.0,
                            severity="HIGH",
                            cwe_id="CWE-915",
                            mitre_attack_id="T1078.004",
                            explanation=f"Mass assignment privilege escalation attempt on protected fields: {injected_fields}.",
                            matched_pattern=", ".join(injected_fields),
                        )
            except Exception:
                pass

        # 10. JWT Misuse Check
        auth_hdr = headers.get("authorization", "")
        if auth_hdr.lower().startswith("bearer "):
            token = auth_hdr.split(" ", 1)[1].strip()
            parts = token.split(".")
            if len(parts) >= 2:
                try:
                    hdr_raw = parts[0] + "=" * (-len(parts[0]) % 4)
                    header_json = base64.b64decode(hdr_raw).decode("utf-8", errors="ignore")
                    if JWT_ALG_NONE_REGEX.search(header_json) or len(parts) == 2 or (len(parts) == 3 and not parts[2]):
                        return AttackDetectionResult(
                            detected=True,
                            category="JWT_MISUSE",
                            confidence=98.0,
                            severity="CRITICAL",
                            cwe_id="CWE-347",
                            mitre_attack_id="T1556",
                            explanation="JWT tampering attempt: insecure 'alg': 'none' or stripped signature detected.",
                            matched_pattern="alg: none",
                        )
                except Exception:
                    pass

        # Clean Request
        return AttackDetectionResult(
            detected=False,
            category=None,
            confidence=0.0,
            severity="LOW",
            cwe_id=None,
            mitre_attack_id=None,
            explanation="No advanced attack indicators matched.",
            obfuscation_detected=norm_result.obfuscation_detected,
            detected_techniques=norm_result.detected_techniques,
        )


# Global singleton instance
advanced_attack_detection_engine = AdvancedAttackDetectionEngine()
