"""
PREVENT-X Traffic Replay & Differential Validation Engine
Captures, sanitizes, and replays legitimate and exploit test HTTP fixtures
to verify zero false-positive regressions and confirm vulnerability mitigation.
Integrates directly with Automated Security Validation (MOD-10).
"""

import json
import logging
import re
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.network_defense import TrafficReplayReport
from backend.app.models.virtual_patch import VirtualPatchRule
from backend.app.modules.network_defense.normalization.service import (
    normalization_patch_service,
)

logger = logging.getLogger("preventx.network_defense.replay")

# Sensitive data masking patterns for PII / Credential Sanitization
PASSWORD_REGEX = re.compile(r'("password"\s*:\s*)"[^"]+"', re.IGNORECASE)
TOKEN_REGEX = re.compile(r'(Bearer\s+)[A-Za-z0-9_\-\.]{15,}', re.IGNORECASE)
EMAIL_REGEX = re.compile(r'([a-zA-Z0-9_\-\.]{2})[a-zA-Z0-9_\-\.]+(@[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,})')
API_KEY_REGEX = re.compile(r'("(?:api_key|token|secret)"\s*:\s*)"[^"]+"', re.IGNORECASE)

# Baseline benign fixtures representing real SMB business workflows
STANDARD_BENIGN_FIXTURES: List[Dict[str, Any]] = [
    {"method": "GET", "path": "/api/v1/products", "query": "category=electronics&sort=price_asc&page=1", "body": "", "is_malicious": False},
    {"method": "GET", "path": "/api/v1/search", "query": "q=cotton+saree+designer&limit=25", "body": "", "is_malicious": False},
    {"method": "GET", "path": "/api/v1/orders/ORD-9921", "query": "format=json&include_items=true", "body": "", "is_malicious": False},
    {"method": "POST", "path": "/api/v1/cart/items", "query": "", "body": '{"product_id": 104, "quantity": 3, "color": "blue"}', "is_malicious": False},
    {"method": "POST", "path": "/api/v1/feedback", "query": "", "body": '{"rating": 5, "comment": "Excellent quick delivery!"}', "is_malicious": False},
    {"method": "GET", "path": "/api/v1/inventory", "query": "warehouse=bengaluru-central&status=in_stock", "body": "", "is_malicious": False},
    {"method": "POST", "path": "/api/v1/auth/login", "query": "", "body": '{"email": "user@alphacorp.in", "password": "UserPass123!"}', "is_malicious": False},
    {"method": "GET", "path": "/api/v1/invoices", "query": "year=2026&quarter=Q1", "body": "", "is_malicious": False},
    {"method": "POST", "path": "/api/v1/profile/settings", "query": "", "body": '{"locale": "en_IN", "timezone": "Asia/Kolkata", "theme": "dark"}', "is_malicious": False},
    {"method": "GET", "path": "/api/v1/support/tickets", "query": "priority=medium&page=1", "body": "", "is_malicious": False},
]

# Standard exploit test fixtures used to verify that the patch blocks actual attacks
STANDARD_EXPLOIT_FIXTURES: List[Dict[str, Any]] = [
    {"method": "GET", "path": "/api/v1/search", "query": "q=' UNION SELECT 1,username,password FROM users--", "body": "", "is_malicious": True},
    {"method": "POST", "path": "/api/v1/search", "query": "", "body": '{"query": "1 UNION SELECT 1,2,3--"}', "is_malicious": True},
    {"method": "GET", "path": "/api/v1/products", "query": "id=10; DROP TABLE customers;--", "body": "", "is_malicious": True},
]


class TrafficReplayEngine:
    """
    Orchestrates differential regression testing of virtual patch rules.
    """

    @staticmethod
    def sanitize_payload(payload_str: str) -> str:
        """Sanitizes PII, passwords, and bearer tokens from request text."""
        if not payload_str:
            return ""
        s = PASSWORD_REGEX.sub(r'\1"********"', payload_str)
        s = API_KEY_REGEX.sub(r'\1"********"', s)
        s = TOKEN_REGEX.sub(r'\1********', s)
        s = EMAIL_REGEX.sub(r'\1***\2', s)
        return s

    def run_replay_validation(
        self,
        db: Session,
        organization_id: uuid.UUID,
        rule: VirtualPatchRule,
        custom_fixtures: Optional[List[Dict[str, Any]]] = None,
        max_fixtures: int = 50,
    ) -> TrafficReplayReport:
        """
        Executes traffic replay against a patch rule:
        1. Compiles benign and exploit fixtures.
        2. Evaluates patch rule using normalized inspection.
        3. Identifies False Positives (benign requests wrongly blocked).
        4. Identifies Missed Threats (exploit payloads allowed through).
        5. Computes FP rate and generates an audited report.
        """
        fixtures = list(custom_fixtures or [])
        if not fixtures:
            fixtures.extend(STANDARD_BENIGN_FIXTURES)
            fixtures.extend(STANDARD_EXPLOIT_FIXTURES)

        fixtures = fixtures[:max_fixtures]

        total_benign = 0
        passed_benign = 0
        false_positives: List[Dict[str, Any]] = []
        missed_threats: List[Dict[str, Any]] = []

        for f in fixtures:
            raw_method = f.get("method", "GET")
            raw_path = f.get("path", "/")
            raw_query = f.get("query", "")
            raw_body = f.get("body", "")
            is_malicious = bool(f.get("is_malicious", False))

            combined_raw = f"{raw_query} {raw_body}".strip()
            sanitized_body = self.sanitize_payload(raw_body)
            sanitized_query = self.sanitize_payload(raw_query)

            # Evaluate against patch rule using multi-layer normalizer
            blocked, matched_rule, norm_meta = normalization_patch_service.evaluate_payload_against_patch_rules(
                raw_payload=combined_raw,
                rules=[rule],
            )

            if not is_malicious:
                total_benign += 1
                if blocked:
                    # Legitimate request was blocked -> False Positive!
                    false_positives.append({
                        "method": raw_method,
                        "path": raw_path,
                        "query": sanitized_query,
                        "body": sanitized_body[:100],
                        "tripped_pattern": getattr(rule, "match_conditions", "") or getattr(rule, "config_snippet", ""),
                    })
                else:
                    passed_benign += 1
            else:
                # Malicious fixture expected to be blocked
                if not blocked:
                    # Exploit was missed -> Evasion / Missed Malicious Request!
                    missed_threats.append({
                        "method": raw_method,
                        "path": raw_path,
                        "query": sanitized_query,
                        "body": sanitized_body[:100],
                        "reason": "Exploit payload was not intercepted by patch pattern.",
                    })

        fp_rate = round(len(false_positives) / total_benign if total_benign > 0 else 0.0, 4)
        is_regression_free = (len(false_positives) == 0 and len(missed_threats) == 0)

        report_details = json.dumps({
            "rule_name": rule.rule_name,
            "total_benign": total_benign,
            "passed_benign": passed_benign,
            "false_positive_samples": false_positives[:5],
            "missed_threat_samples": missed_threats[:5],
            "status": "PASS" if is_regression_free else "FAIL",
        })

        report = TrafficReplayReport(
            organization_id=organization_id,
            virtual_patch_id=rule.id,
            total_replayed=len(fixtures),
            passed_benign=passed_benign,
            false_positives=len(false_positives),
            missed_threats=len(missed_threats),
            fp_rate=fp_rate,
            is_regression_free=is_regression_free,
            report_details=report_details,
        )
        db.add(report)
        db.commit()
        db.refresh(report)

        logger.info(
            "Replay completed for rule '%s': %d fixtures, FP=%d, Missed=%d, Clean=%s",
            rule.rule_name,
            len(fixtures),
            len(false_positives),
            len(missed_threats),
            is_regression_free,
        )
        return report


# Global replay engine instance
traffic_replay_engine = TrafficReplayEngine()
