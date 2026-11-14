"""
PREVENT-X Intelligent Virtual Patch Generator (MOD-06)
Deterministically synthesizes explainable compensating virtual patch specifications
from CVE, CWE, vulnerability evidence, and attack path intelligence.

MANDATE: AI recommendations must never automatically become production rules without human validation.
"""

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.asset import ManagedAsset
from backend.app.models.virtual_patch import (
    AttackType,
    PatchAction,
    PatchStatus,
    VirtualPatchRecommendation,
    VirtualPatchRule,
    VirtualPatchVersion,
)
from backend.app.models.vulnerability import VulnerabilityRecord

logger = logging.getLogger("preventx.virtual_patch.generator")

# Deterministic signature catalog for prominent CWE categories
CWE_ATTACK_SIGNATURES = {
    # SQL Injection (CWE-89)
    "CWE-89": {
        "attack_type": AttackType.SQLI.value,
        "name_prefix": "Virtual Patch: SQL Injection Protection",
        "patterns": [
            r"(?i)(union\s+all\s+select|union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table)",
            r"(?i)('\s*(or|and)\s*('|[0-9]+=[0-9]+|true)|--\s*$|;\s*--)",
            r"(?i)(waitfor\s+delay|sleep\s*\(|benchmark\s*\(|pg_sleep\s*\()",
        ],
        "rationale": "Compensates for SQL injection flaws (CWE-89) by terminating requests containing unauthorized SQL keywords, tautologies, or blind timing payloads at the gateway tier.",
        "default_target": "QUERY",
    },
    # Cross-Site Scripting (CWE-79)
    "CWE-79": {
        "attack_type": AttackType.XSS.value,
        "name_prefix": "Virtual Patch: Cross-Site Scripting (XSS) Filter",
        "patterns": [
            r"(?i)((<|%3c)script[\s>%]|javascript:|vbscript:|data:text/html)",
            r"(?i)(onerror\s*=|onload\s*=|onclick\s*=|onmouseover\s*=|onfocus\s*=)",
            r"(?i)(document\.cookie|document\.location|window\.location|eval\s*\()",
        ],
        "rationale": "Neutralizes client-side script injection (CWE-79) by rejecting non-sanitized HTML tags, script attributes, and DOM manipulation expressions in user inputs.",
        "default_target": "QUERY",
    },
    # Path Traversal (CWE-22)
    "CWE-22": {
        "attack_type": AttackType.PATH_TRAVERSAL.value,
        "name_prefix": "Virtual Patch: Directory Traversal Restriction",
        "patterns": [
            r"(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c)",
            r"(?i)(/etc/passwd|/etc/shadow|/proc/self|win\.ini|boot\.ini|windows[\\/]system32)",
        ],
        "rationale": "Prevents unauthorized file system escape (CWE-22) by blocking directory escalation sequences and references to critical operating system files.",
        "default_target": "URI",
    },
    # Command Injection (CWE-78)
    "CWE-78": {
        "attack_type": AttackType.CMDI.value,
        "name_prefix": "Virtual Patch: OS Command Injection Barrier",
        "patterns": [
            r"(?i)((;|%3b)\s*(cat|ls|id|whoami|curl|wget|nc|sh|bash|powershell)|(\| |%7c)\s*(cat|ls|id|whoami|sh|bash)|\$\(.*\)|`.*`)",
            r"(?i)(/bin/(bash|sh|zsh)|cmd\.exe|powershell(\.exe)?)",
        ],
        "rationale": "Blocks shell operator chaining and binary execution triggers (CWE-78) attempting to hijack host operating system commands.",
        "default_target": "QUERY",
    },
    # Known Vulnerable Request Scanners & Probes
    "SCANNERS": {
        "attack_type": AttackType.PATTERN_BLOCK.value,
        "name_prefix": "Virtual Patch: Automated Vulnerability Scanner Blocker",
        "patterns": [
            r"(?i)(sqlmap|nikto|dirbuster|gobuster|wpscan|nmap|masscan|zgrab)",
        ],
        "rationale": "Blocks identified malicious reconnaissance tools and automated exploit frameworks before target discovery.",
        "default_target": "HEADER",
        "header_name": "User-Agent",
    },
}


class IntelligentVirtualPatchGenerator:
    """
    Synthesizes explainable virtual patch recommendations and converts them into production rules.
    """

    @classmethod
    def synthesize_recommendation_for_vulnerability(
        cls,
        vulnerability: VulnerabilityRecord,
        asset: ManagedAsset,
    ) -> Optional[VirtualPatchRecommendation]:
        """
        Derives an explainable virtual patch recommendation from a vulnerability record.
        """
        title = (vulnerability.title or "").upper()
        desc = (vulnerability.description or "").upper()
        cve = vulnerability.cve_id or "GENERIC-VULN"

        # Determine matched attack signature
        matched_sig = None
        cwe_code = "CWE-89"  # Default fallback to SQLi if injection

        if "SQL" in title or "SQL" in desc or "INJECTION" in title:
            cwe_code = "CWE-89"
            matched_sig = CWE_ATTACK_SIGNATURES["CWE-89"]
        elif "XSS" in title or "SCRIPT" in title or "CROSS-SITE" in title or "CROSS SITE" in desc:
            cwe_code = "CWE-79"
            matched_sig = CWE_ATTACK_SIGNATURES["CWE-79"]
        elif "TRAVERSAL" in title or "DIRECTORY" in title or "PATH" in title:
            cwe_code = "CWE-22"
            matched_sig = CWE_ATTACK_SIGNATURES["CWE-22"]
        elif "COMMAND" in title or "RCE" in title or "EXECUTION" in title:
            cwe_code = "CWE-78"
            matched_sig = CWE_ATTACK_SIGNATURES["CWE-78"]
        else:
            # Fallback based on severity
            cwe_code = "CWE-89"
            matched_sig = CWE_ATTACK_SIGNATURES["CWE-89"]

        # Composite regex pattern with leading (?i) flag
        clean_patterns = [p.replace("(?i)", "") for p in matched_sig["patterns"]]
        combined_pattern = "(?i)(" + "|".join(f"({p})" for p in clean_patterns) + ")"
        rule_name = f"{matched_sig['name_prefix']} [{cve}]"

        # Calculate recommendation confidence
        base_confidence = 85
        if vulnerability.severity == "CRITICAL":
            base_confidence = 95
        elif vulnerability.severity == "HIGH":
            base_confidence = 90

        rec = VirtualPatchRecommendation(
            id=uuid.uuid4(),
            organization_id=vulnerability.organization_id,
            vulnerability_id=vulnerability.id,
            asset_id=asset.id,
            cve_id=vulnerability.cve_id,
            cwe_id=cwe_code,
            attack_type=matched_sig["attack_type"],
            suggested_rule_name=rule_name,
            suggested_pattern=combined_pattern,
            target_uri_pattern="/.*",
            rationale=f"{matched_sig['rationale']} Derived specifically for target '{asset.name}' ({asset.target}).",
            confidence=base_confidence,
            status="PROPOSED",
        )
        return rec

    @classmethod
    def create_rule_from_recommendation(
        cls,
        db: Session,
        recommendation: VirtualPatchRecommendation,
        user_id: Optional[uuid.UUID] = None,
    ) -> VirtualPatchRule:
        """
        Converts an approved recommendation into an active WAF draft rule with versioning.
        """
        match_conditions = [
            {
                "target": "QUERY",
                "operator": "REGEX",
                "pattern": recommendation.suggested_pattern,
                "is_case_sensitive": False,
            },
            {
                "target": "URI",
                "operator": "REGEX",
                "pattern": recommendation.suggested_pattern,
                "is_case_sensitive": False,
            },
        ]

        rule = VirtualPatchRule(
            id=uuid.uuid4(),
            organization_id=recommendation.organization_id,
            asset_id=recommendation.asset_id,
            vulnerability_id=recommendation.vulnerability_id,
            cve_id=recommendation.cve_id,
            cwe_id=recommendation.cwe_id,
            rule_name=recommendation.suggested_rule_name,
            attack_type=recommendation.attack_type,
            description=recommendation.rationale,
            severity="HIGH",
            priority=100,
            action=PatchAction.BLOCK.value,
            target_uri_pattern=recommendation.target_uri_pattern or "/.*",
            http_methods=json.dumps(["GET", "POST", "PUT", "DELETE", "PATCH"]),
            match_conditions=json.dumps(match_conditions),
            status=PatchStatus.DRAFT.value,
            is_active=True,
            is_system_rule=False,
            version=1,
        )
        db.add(rule)
        db.flush()

        # Create initial Version 1 record
        version_rec = VirtualPatchVersion(
            id=uuid.uuid4(),
            rule_id=rule.id,
            version_number=1,
            rule_name=rule.rule_name,
            action=rule.action,
            target_uri_pattern=rule.target_uri_pattern,
            match_conditions=rule.match_conditions,
            change_summary="Initial synthesis from recommendation",
            created_by_user_id=user_id,
        )
        db.add(version_rec)

        recommendation.status = "ACCEPTED"
        recommendation.generated_rule_id = rule.id
        db.flush()

        return rule

    @classmethod
    def create_default_baseline_rules(
        cls,
        db: Session,
        organization_id: uuid.UUID,
    ) -> List[VirtualPatchRule]:
        """
        Generates core baseline virtual patch rules (SQLi, XSS, Path Traversal, Scanners)
        for a tenant organization.
        """
        created = []
        priority = 50

        for key, sig in CWE_ATTACK_SIGNATURES.items():
            clean_patterns = [p.replace("(?i)", "") for p in sig["patterns"]]
            combined_pattern = "(?i)(" + "|".join(f"({p})" for p in clean_patterns) + ")"
            target = sig.get("default_target", "QUERY")
            header_name = sig.get("header_name")

            match_conditions = [
                {
                    "target": target,
                    "header_name": header_name,
                    "operator": "REGEX",
                    "pattern": combined_pattern,
                    "is_case_sensitive": False,
                }
            ]

            rule = VirtualPatchRule(
                id=uuid.uuid4(),
                organization_id=organization_id,
                rule_name=f"Baseline Protection: {sig['name_prefix'].replace('Virtual Patch: ', '')}",
                attack_type=sig["attack_type"],
                description=sig["rationale"],
                severity="HIGH",
                priority=priority,
                action=PatchAction.BLOCK.value,
                target_uri_pattern="/.*",
                http_methods=json.dumps(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]),
                match_conditions=json.dumps(match_conditions),
                status=PatchStatus.APPROVED.value,
                is_active=True,
                is_system_rule=True,
                version=1,
            )
            db.add(rule)
            db.flush()

            version_rec = VirtualPatchVersion(
                id=uuid.uuid4(),
                rule_id=rule.id,
                version_number=1,
                rule_name=rule.rule_name,
                action=rule.action,
                target_uri_pattern=rule.target_uri_pattern,
                match_conditions=rule.match_conditions,
                change_summary="Standard baseline virtual patch deployment",
            )
            db.add(version_rec)
            created.append(rule)
            priority += 20

        # Method restriction rule (drop TRACE, TRACK, CONNECT, DEBUG)
        method_rule = VirtualPatchRule(
            id=uuid.uuid4(),
            organization_id=organization_id,
            rule_name="Baseline Protection: Insecure HTTP Method Restriction",
            attack_type=AttackType.METHOD_RESTRICTION.value,
            description="Restricts HTTP verbs to standard safe operations, blocking TRACE, TRACK, and arbitrary methods.",
            severity="MEDIUM",
            priority=10,
            action=PatchAction.BLOCK.value,
            target_uri_pattern="/.*",
            http_methods=json.dumps(["TRACE", "TRACK", "CONNECT", "DEBUG"]),
            match_conditions=json.dumps([]),
            status=PatchStatus.APPROVED.value,
            is_active=True,
            is_system_rule=True,
            version=1,
        )
        db.add(method_rule)
        created.append(method_rule)

        db.flush()
        return created
