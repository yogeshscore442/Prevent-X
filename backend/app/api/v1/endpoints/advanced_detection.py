"""
PREVENT-X Advanced Attack Detection REST API
Provides endpoints for inspecting requests against the 10 extended attack categories.
"""

from typing import Dict, List
from fastapi import APIRouter, Depends, HTTPException, status

from backend.app.models.organization import Organization
from backend.app.modules.network_defense.detection.engine import (
    advanced_attack_detection_engine,
)
from backend.app.schemas.network_defense import (
    AttackDetectionRequest,
    AttackDetectionResponse,
)
from backend.app.security.permissions import (
    PermissionCode,
    get_current_organization,
    require_permission,
)

router = APIRouter(prefix="/network-defense/detection", tags=["Advanced Network Defense - Attack Detection"])


@router.post(
    "/inspect",
    response_model=AttackDetectionResponse,
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def inspect_http_traffic(
    payload: AttackDetectionRequest,
    org: Organization = Depends(get_current_organization),
):
    """
    Evaluates HTTP request telemetry through all 10 advanced attack detectors:
    SSRF, XXE, SSTI, NoSQLi, LDAPi, Open Redirect, Request Smuggling,
    GraphQL Abuse, Mass Assignment, and JWT Misuse.
    """
    res = advanced_attack_detection_engine.inspect_request(
        method=payload.method,
        path=payload.path,
        query_string=payload.query_string,
        body=payload.body,
        headers=payload.headers,
    )
    return AttackDetectionResponse(
        detected=res.detected,
        category=res.category,
        confidence=res.confidence,
        severity=res.severity,
        cwe_id=res.cwe_id,
        mitre_attack_id=res.mitre_attack_id,
        explanation=res.explanation,
        matched_pattern=res.matched_pattern,
        obfuscation_detected=res.obfuscation_detected,
        detected_techniques=res.detected_techniques or [],
    )


@router.get(
    "/categories",
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def list_detection_categories():
    """Lists supported advanced detection modules with CWE and MITRE mappings."""
    return [
        {"category": "SSRF", "cwe": "CWE-918", "mitre": "T1090.003", "name": "Server-Side Request Forgery"},
        {"category": "XXE", "cwe": "CWE-611", "mitre": "T1190", "name": "XML External Entity Injection"},
        {"category": "SSTI", "cwe": "CWE-1336", "mitre": "T1059", "name": "Server-Side Template Injection"},
        {"category": "NOSQL_INJECTION", "cwe": "CWE-943", "mitre": "T1190", "name": "NoSQL Operator Injection"},
        {"category": "LDAP_INJECTION", "cwe": "CWE-90", "mitre": "T1078", "name": "LDAP Directory Filter Injection"},
        {"category": "OPEN_REDIRECT", "cwe": "CWE-601", "mitre": "T1566.002", "name": "Unvalidated Open Redirect"},
        {"category": "HTTP_REQUEST_SMUGGLING", "cwe": "CWE-444", "mitre": "T1071.001", "name": "HTTP Request Smuggling"},
        {"category": "GRAPHQL_ABUSE", "cwe": "CWE-400", "mitre": "T1499", "name": "GraphQL Recursive Depth / Introspection Abuse"},
        {"category": "MASS_ASSIGNMENT", "cwe": "CWE-915", "mitre": "T1078.004", "name": "Mass Assignment Privilege Escalation"},
        {"category": "JWT_MISUSE", "cwe": "CWE-347", "mitre": "T1556", "name": "JWT Algorithm None & Signature Tampering"},
    ]
