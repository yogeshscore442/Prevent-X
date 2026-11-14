"""
PREVENT-X Deterministic Exposure Risk Engine
Calculates an objective, explainable, and reproducible 0–100 exposure risk score based on observed attack surface signals.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from backend.app.modules.attack_surface.interfaces import RiskScoringEngineInterface


class DeterministicRiskEngine(RiskScoringEngineInterface):
    """
    Computes explainable attack surface exposure risk.
    Guarantees full mathematical transparency without opaque heuristics or CVE assumptions.
    """

    def calculate_risk(
        self,
        domain_name: str,
        subdomains: List[str],
        dns_data: Dict[str, Any],
        certificates: List[Dict[str, Any]],
        rdap_data: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Executes multi-factor exposure risk evaluation.
        """
        factors: List[Dict[str, Any]] = []
        total_score = 0.0
        now = datetime.now(timezone.utc)

        # 1. Subdomain Sprawl Factor (Weight: 25.0)
        subdomain_count = len(subdomains)
        sprawl_score = 0.0
        if subdomain_count > 20:
            sprawl_score = 25.0
            sprawl_desc = f"Extensive attack surface sprawl with {subdomain_count} discovered subdomains."
            sprawl_impact = "HIGH"
        elif subdomain_count > 5:
            sprawl_score = 15.0
            sprawl_desc = f"Moderate attack surface footprint with {subdomain_count} discovered subdomains."
            sprawl_impact = "MEDIUM"
        elif subdomain_count > 1:
            sprawl_score = 5.0
            sprawl_desc = f"Contained footprint with {subdomain_count} discovered subdomains."
            sprawl_impact = "LOW"
        else:
            sprawl_desc = "Single apex domain detected without external subdomain exposure."
            sprawl_impact = "INFO"

        factors.append({
            "name": "Subdomain Sprawl",
            "factor_key": "subdomain_sprawl",
            "score": sprawl_score,
            "max_weight": 25.0,
            "impact": sprawl_impact,
            "description": sprawl_desc,
        })
        total_score += sprawl_score

        # 2. Wildcard Certificate Exposure (Weight: 15.0)
        has_wildcard = any(cert.get("is_wildcard", False) for cert in certificates)
        wildcard_score = 15.0 if has_wildcard else 0.0
        factors.append({
            "name": "Wildcard Certificate Exposure",
            "factor_key": "wildcard_certificates",
            "score": wildcard_score,
            "max_weight": 15.0,
            "impact": "MEDIUM" if has_wildcard else "INFO",
            "description": "Wildcard certificate detected, expanding the blast radius across all subdomains."
            if has_wildcard else "No wildcard certificates observed.",
        })
        total_score += wildcard_score

        # 3. Certificate Expiration & Validity (Weight: 20.0)
        has_expired = False
        expiring_soon = False
        for cert in certificates:
            if cert.get("is_expired"):
                has_expired = True
                break
            not_after = cert.get("not_after")
            if not_after:
                delta = (not_after - now).total_days() if hasattr((not_after - now), "total_days") else (not_after - now).days
                if delta < 30:
                    expiring_soon = True

        cert_score = 0.0
        if has_expired:
            cert_score = 20.0
            cert_desc = "One or more expired TLS certificates active in observed logs, leading to service disruption or trust breakdown."
            cert_impact = "CRITICAL"
        elif expiring_soon:
            cert_score = 10.0
            cert_desc = "TLS certificate expiring within 30 days, requiring renewal attention."
            cert_impact = "MEDIUM"
        else:
            cert_desc = "TLS certificates possess valid timelines."
            cert_impact = "INFO"

        factors.append({
            "name": "Certificate Validity Posture",
            "factor_key": "certificate_validity",
            "score": cert_score,
            "max_weight": 20.0,
            "impact": cert_impact,
            "description": cert_desc,
        })
        total_score += cert_score

        # 4. Email Security Posture (SPF & DMARC) (Weight: 20.0)
        has_spf = bool(dns_data.get("spf_record"))
        has_dmarc = bool(dns_data.get("dmarc_record"))
        email_score = 0.0

        if not has_spf and not has_dmarc:
            email_score = 20.0
            email_desc = "Missing both SPF and DMARC records on domain, enabling domain spoofing and email impersonation."
            email_impact = "HIGH"
        elif not has_dmarc:
            email_score = 10.0
            email_desc = "SPF present but DMARC policy is missing, leaving outbound email protection unmonitored."
            email_impact = "MEDIUM"
        elif not has_spf:
            email_score = 10.0
            email_desc = "DMARC declared but SPF record missing from DNS."
            email_impact = "MEDIUM"
        else:
            email_desc = "Both SPF and DMARC policies are configured."
            email_impact = "INFO"

        factors.append({
            "name": "Email Spoofing Protection (SPF/DMARC)",
            "factor_key": "email_security",
            "score": email_score,
            "max_weight": 20.0,
            "impact": email_impact,
            "description": email_desc,
        })
        total_score += email_score

        # 5. Dangling CNAME & Takeover Risk (Weight: 15.0)
        dangling_candidates = dns_data.get("dangling_cname_candidates", [])
        dangling_score = 15.0 if dangling_candidates else 0.0
        factors.append({
            "name": "Dangling CNAME / Cloud Takeover",
            "factor_key": "dangling_cname",
            "score": dangling_score,
            "max_weight": 15.0,
            "impact": "HIGH" if dangling_candidates else "INFO",
            "description": f"Observed CNAME targets pointing to external third-party cloud hosting ({', '.join(dangling_candidates[:2])}), susceptible to takeover if unclaimed."
            if dangling_candidates else "No dangling third-party CNAME pointers identified.",
        })
        total_score += dangling_score

        # 6. Infrastructure Footprint & Internal IP Exposure (Weight: 10.0)
        internal_ips = dns_data.get("internal_ips_detected", [])
        public_ips = dns_data.get("public_ips", [])
        infra_score = 0.0

        if internal_ips:
            infra_score = 10.0
            infra_desc = f"Private/RFC1918 IP addresses ({', '.join(internal_ips)}) exposed in public DNS records, leaking internal network architecture."
            infra_impact = "HIGH"
        elif len(public_ips) > 5:
            infra_score = 5.0
            infra_desc = f"Distributed infrastructure footprint across {len(public_ips)} public IP endpoints."
            infra_impact = "LOW"
        else:
            infra_desc = f"Infrastructure points to {len(public_ips)} public IP addresses."
            infra_impact = "INFO"

        factors.append({
            "name": "Infrastructure & IP Exposure",
            "factor_key": "ip_exposure",
            "score": infra_score,
            "max_weight": 10.0,
            "impact": infra_impact,
            "description": infra_desc,
        })
        total_score += infra_score

        # Final score normalisation
        bounded_score = round(min(max(total_score, 0.0), 100.0), 1)

        if bounded_score >= 75.0:
            risk_level = "CRITICAL"
            interpretation = "Severe attack surface exposure with elevated external takeover or spoofing risks."
        elif bounded_score >= 50.0:
            risk_level = "HIGH"
            interpretation = "Notable attack surface exposures requiring remediation of email security or DNS pointers."
        elif bounded_score >= 20.0:
            risk_level = "MEDIUM"
            interpretation = "Moderate exposure posture with routine external asset footprint."
        else:
            risk_level = "LOW"
            interpretation = "Minimal attack surface exposure with standard defensive hygiene."

        return {
            "total_score": bounded_score,
            "risk_level": risk_level,
            "factors": factors,
            "interpretation": interpretation,
        }
