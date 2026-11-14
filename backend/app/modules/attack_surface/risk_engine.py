"""
PREVENT-X Deterministic Exposure Risk Engine
Calculates an objective, explainable, and mathematically normalized 0–100 exposure risk score.
Distinguishes exposure indicators from vulnerabilities, availability from exploitability,
and email posture from application perimeter.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from backend.app.models.attack_surface import FindingCategory, TakeoverVerificationStatus
from backend.app.modules.attack_surface.interfaces import RiskScoringEngineInterface


class DeterministicRiskEngine(RiskScoringEngineInterface):
    """
    Computes explainable attack surface exposure risk.
    Guarantees that the sum of maximum weights is mathematically exactly 100.0.
    """

    # Normalized factor weight definitions summing to exactly 100.0
    WEIGHT_PERIMETER_SPRAWL = 20.0
    WEIGHT_TLS_SCOPE_POSTURE = 15.0
    WEIGHT_AVAILABILITY_EXPIRY = 20.0
    WEIGHT_EMAIL_SPOOFING_DEFENSE = 20.0
    WEIGHT_RESOURCE_TAKEOVER = 15.0
    WEIGHT_TOPOLOGY_EXPOSURE = 10.0

    TOTAL_MAX_WEIGHT = (
        WEIGHT_PERIMETER_SPRAWL
        + WEIGHT_TLS_SCOPE_POSTURE
        + WEIGHT_AVAILABILITY_EXPIRY
        + WEIGHT_EMAIL_SPOOFING_DEFENSE
        + WEIGHT_RESOURCE_TAKEOVER
        + WEIGHT_TOPOLOGY_EXPOSURE
    )  # Exactly 100.0

    def calculate_risk(
        self,
        domain_name: str,
        subdomains: List[str],
        dns_data: Dict[str, Any],
        certificates: List[Dict[str, Any]],
        rdap_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Executes multi-factor exposure risk evaluation.
        """
        factors: List[Dict[str, Any]] = []
        total_score = 0.0
        now = datetime.now(timezone.utc)

        # ----------------------------------------------------------------------
        # Factor 1: Perimeter Breadth & Subdomain Sprawl (Max: 20.0 pts)
        # Note: Exposure indicator, NOT proof of compromise.
        # ----------------------------------------------------------------------
        subdomain_count = len(subdomains)
        if subdomain_count > 20:
            sprawl_score = self.WEIGHT_PERIMETER_SPRAWL
            sprawl_desc = f"Extensive external perimeter footprint with {subdomain_count} discovered subdomains."
            sprawl_impact = "HIGH"
        elif subdomain_count > 5:
            sprawl_score = 12.0
            sprawl_desc = f"Moderate perimeter footprint with {subdomain_count} discovered subdomains."
            sprawl_impact = "MEDIUM"
        elif subdomain_count > 1:
            sprawl_score = 5.0
            sprawl_desc = f"Contained perimeter footprint with {subdomain_count} discovered subdomains."
            sprawl_impact = "LOW"
        else:
            sprawl_score = 0.0
            sprawl_desc = "Single apex domain detected without external subdomain exposure."
            sprawl_impact = "INFO"

        factors.append({
            "name": "Perimeter Breadth & Subdomain Sprawl",
            "factor_key": "subdomain_sprawl",
            "category": FindingCategory.ATTACK_SURFACE_EXPOSURE,
            "score": round(sprawl_score, 1),
            "max_weight": self.WEIGHT_PERIMETER_SPRAWL,
            "impact": sprawl_impact,
            "confidence": 0.95,
            "evidence_quality": "HIGH",
            "is_vulnerability": False,
            "description": sprawl_desc,
        })
        total_score += sprawl_score

        # ----------------------------------------------------------------------
        # Factor 2: Certificate & TLS Scope Posture (Max: 15.0 pts)
        # Note: Wildcard certificates broaden blast radius across hostnames,
        # but are architectural indicators, NOT vulnerabilities.
        # ----------------------------------------------------------------------
        has_wildcard = any(cert.get("is_wildcard", False) for cert in certificates)
        tls_scope_score = self.WEIGHT_TLS_SCOPE_POSTURE if has_wildcard else 0.0
        factors.append({
            "name": "Certificate & TLS Scope Posture",
            "factor_key": "tls_scope_posture",
            "category": FindingCategory.CERTIFICATE_TLS_POSTURE,
            "score": round(tls_scope_score, 1),
            "max_weight": self.WEIGHT_TLS_SCOPE_POSTURE,
            "impact": "MEDIUM" if has_wildcard else "INFO",
            "confidence": 0.90,
            "evidence_quality": "HIGH",
            "is_vulnerability": False,
            "description": "Wildcard certificate (*.) detected. While convenient, wildcard keys broaden compromise blast radius across all subdomains."
            if has_wildcard else "No wildcard certificates observed; scoped single-host certificates in use.",
        })
        total_score += tls_scope_score

        # ----------------------------------------------------------------------
        # Factor 3: Service Availability & Certificate Validity (Max: 20.0 pts)
        # Note: Availability and cryptographic trust breakdown, NOT code exploitability.
        # ----------------------------------------------------------------------
        has_expired = False
        expiring_14_days = False
        expiring_30_days = False

        for cert in certificates:
            if cert.get("is_expired"):
                has_expired = True
                break
            not_after = cert.get("not_after")
            if not_after:
                delta_days = (not_after - now).days if hasattr((not_after - now), "days") else 365
                if delta_days < 14:
                    expiring_14_days = True
                elif delta_days < 30:
                    expiring_30_days = True

        if has_expired:
            avail_score = self.WEIGHT_AVAILABILITY_EXPIRY
            avail_desc = "Expired TLS certificate observed in active telemetry, creating service disruption and browser trust blockage."
            avail_impact = "CRITICAL"
        elif expiring_14_days:
            avail_score = 10.0
            avail_desc = "TLS certificate expires within 14 days; immediate renewal required to prevent service outage."
            avail_impact = "HIGH"
        elif expiring_30_days:
            avail_score = 5.0
            avail_desc = "TLS certificate expires within 30 days; renewal planned maintenance window advised."
            avail_impact = "MEDIUM"
        else:
            avail_score = 0.0
            avail_desc = "Active TLS certificates possess healthy validity timelines."
            avail_impact = "INFO"

        factors.append({
            "name": "Service Availability & Certificate Validity",
            "factor_key": "certificate_validity",
            "category": FindingCategory.CERTIFICATE_TLS_POSTURE,
            "score": round(avail_score, 1),
            "max_weight": self.WEIGHT_AVAILABILITY_EXPIRY,
            "impact": avail_impact,
            "confidence": 0.95,
            "evidence_quality": "HIGH",
            "is_vulnerability": False,
            "description": avail_desc,
        })
        total_score += avail_score

        # ----------------------------------------------------------------------
        # Factor 4: Email Security Posture (SPF & DMARC) (Max: 20.0 pts)
        # Note: Domain spoofing & brand impersonation defense, evaluated separately
        # from web application exposure.
        # ----------------------------------------------------------------------
        has_spf = bool(dns_data.get("spf_record"))
        has_dmarc = bool(dns_data.get("dmarc_record"))

        if not has_spf and not has_dmarc:
            email_score = self.WEIGHT_EMAIL_SPOOFING_DEFENSE
            email_desc = "Missing both SPF and DMARC authentication policies, allowing unauthorized parties to spoof emails from this domain."
            email_impact = "HIGH"
        elif not has_dmarc:
            email_score = 10.0
            email_desc = "SPF present but DMARC policy is missing; receiving servers lack enforcement rules for failed sender authentication."
            email_impact = "MEDIUM"
        elif not has_spf:
            email_score = 10.0
            email_desc = "DMARC record declared but SPF record missing from DNS apex."
            email_impact = "MEDIUM"
        else:
            email_score = 0.0
            email_desc = "Both SPF sender policy and DMARC enforcement records are configured."
            email_impact = "INFO"

        factors.append({
            "name": "Email Spoofing Defense (SPF & DMARC)",
            "factor_key": "email_security_posture",
            "category": FindingCategory.EMAIL_SECURITY_POSTURE,
            "score": round(email_score, 1),
            "max_weight": self.WEIGHT_EMAIL_SPOOFING_DEFENSE,
            "impact": email_impact,
            "confidence": 0.95,
            "evidence_quality": "HIGH",
            "is_vulnerability": False,
            "description": email_desc,
        })
        total_score += email_score

        # ----------------------------------------------------------------------
        # Factor 5: Potential Resource Takeover Indicators (Max: 15.0 pts)
        # Note: Differentiates confirmed unclaimed resources from unverified pointers.
        # ----------------------------------------------------------------------
        cname_status = dns_data.get("cname_takeover_status")
        dangling_candidates = dns_data.get("dangling_cname_candidates", [])

        if cname_status == TakeoverVerificationStatus.VERIFIED_UNCLAIMED_RESOURCE:
            takeover_score = self.WEIGHT_RESOURCE_TAKEOVER
            takeover_desc = f"Verified unclaimed external resource detected: CNAME alias points to non-existent cloud tenant ({', '.join(dangling_candidates[:2])})."
            takeover_impact = "HIGH"
            takeover_quality = "HIGH"
        elif dangling_candidates:
            takeover_score = 7.5
            takeover_desc = f"Potential dangling CNAME pointer identified to third-party cloud hosting ({', '.join(dangling_candidates[:2])}); unverified."
            takeover_impact = "MEDIUM"
            takeover_quality = "MEDIUM"
        else:
            takeover_score = 0.0
            takeover_desc = "No dangling third-party cloud CNAME pointers observed."
            takeover_impact = "INFO"
            takeover_quality = "HIGH"

        factors.append({
            "name": "Resource Takeover Indicators",
            "factor_key": "resource_takeover",
            "category": FindingCategory.RESOURCE_TAKEOVER_INDICATOR,
            "score": round(takeover_score, 1),
            "max_weight": self.WEIGHT_RESOURCE_TAKEOVER,
            "impact": takeover_impact,
            "confidence": 0.85 if cname_status == TakeoverVerificationStatus.VERIFIED_UNCLAIMED_RESOURCE else 0.60,
            "evidence_quality": takeover_quality,
            "is_vulnerability": False,
            "description": takeover_desc,
        })
        total_score += takeover_score

        # ----------------------------------------------------------------------
        # Factor 6: Network Boundary & Topology Exposure (Max: 10.0 pts)
        # ----------------------------------------------------------------------
        internal_ips = dns_data.get("internal_ips_detected", [])
        public_ips = dns_data.get("public_ips", [])

        if internal_ips:
            topology_score = self.WEIGHT_TOPOLOGY_EXPOSURE
            topology_desc = f"RFC 1918 private IP addresses ({', '.join(internal_ips)}) exposed in public DNS records, leaking internal network architecture."
            topology_impact = "HIGH"
        elif len(public_ips) > 10:
            topology_score = 5.0
            topology_desc = f"Distributed infrastructure footprint across {len(public_ips)} distinct public IP endpoints."
            topology_impact = "LOW"
        else:
            topology_score = 0.0
            topology_desc = f"Standard infrastructure footprint across {len(public_ips)} public IP endpoints."
            topology_impact = "INFO"

        factors.append({
            "name": "Network Topology & IP Exposure",
            "factor_key": "topology_exposure",
            "category": FindingCategory.DNS_CONFIGURATION_WEAKNESS,
            "score": round(topology_score, 1),
            "max_weight": self.WEIGHT_TOPOLOGY_EXPOSURE,
            "impact": topology_impact,
            "confidence": 0.95,
            "evidence_quality": "HIGH",
            "is_vulnerability": False,
            "description": topology_desc,
        })
        total_score += topology_score

        # Mathematical normalization guarantee: strictly bounded between 0.0 and 100.0
        final_score = round(min(max(total_score, 0.0), 100.0), 1)

        if final_score >= 75.0:
            risk_level = "CRITICAL"
            interpretation = "Severe attack surface exposure with elevated external takeover or availability disruption risks."
        elif final_score >= 50.0:
            risk_level = "HIGH"
            interpretation = "Notable attack surface exposure requiring remediation of email security or cloud resource pointers."
        elif final_score >= 20.0:
            risk_level = "MEDIUM"
            interpretation = "Moderate exposure posture with routine external asset footprint and active maintenance requirements."
        else:
            risk_level = "LOW"
            interpretation = "Minimal attack surface exposure with standard defensive hygiene and contained external perimeter."

        return {
            "total_score": final_score,
            "max_possible_score": 100.0,
            "risk_level": risk_level,
            "factors": factors,
            "interpretation": interpretation,
        }
