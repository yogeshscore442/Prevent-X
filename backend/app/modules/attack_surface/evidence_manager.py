"""
PREVENT-X Evidence Manager
Synthesizes multi-source passive telemetry into categorized, actionable Exposure Findings.
"""

from datetime import datetime, timezone
import json
from typing import List, Dict, Any, Optional
from uuid import UUID
from backend.app.models.attack_surface import (
    ExposureFinding,
    FindingCategory,
    FindingSeverity,
    FindingConfidence,
)


class EvidenceManager:
    """Consolidates raw telemetry into formal Exposure Findings."""

    @classmethod
    def generate_findings_for_job(
        cls,
        organization_id: UUID,
        asset_id: UUID,
        job_id: UUID,
        target_domain: str,
        discovered_domains: List[str],
        dns_data: Dict[str, Any],
        certificates: List[Dict[str, Any]],
        rdap_data: Optional[Dict[str, Any]],
        known_asset_targets: List[str],
    ) -> List[ExposureFinding]:
        """
        Creates structured ExposureFinding records with full JSON evidence payloads.
        """
        findings: List[ExposureFinding] = []
        now = datetime.now(timezone.utc)

        # 1. Base Domain Discovery Finding
        findings.append(
            ExposureFinding(
                organization_id=organization_id,
                asset_id=asset_id,
                job_id=job_id,
                target=target_domain,
                finding_category=FindingCategory.PUBLIC_DOMAIN,
                severity=FindingSeverity.INFO,
                confidence=FindingConfidence.HIGH,
                title=f"Public Domain Exposure: {target_domain}",
                description=f"Primary domain '{target_domain}' is actively exposed on the public internet.",
                evidence=json.dumps({
                    "domain": target_domain,
                    "registrar": rdap_data.get("registrar_name") if rdap_data else "Unknown",
                    "public_ips": dns_data.get("public_ips", []),
                }),
                discovery_source="PASSIVE_RECON",
                first_observed_at=now,
                last_observed_at=now,
                current_status="ACTIVE",
            )
        )

        # 2. Discovered Subdomains
        for sub in discovered_domains:
            if sub != target_domain:
                is_known = sub in known_asset_targets
                cat = FindingCategory.DISCOVERED_SUBDOMAIN if is_known else FindingCategory.UNKNOWN_ASSET_RELATIONSHIP
                sev = FindingSeverity.LOW if is_known else FindingSeverity.MEDIUM
                findings.append(
                    ExposureFinding(
                        organization_id=organization_id,
                        asset_id=asset_id,
                        job_id=job_id,
                        target=sub,
                        finding_category=cat,
                        severity=sev,
                        confidence=FindingConfidence.HIGH,
                        title=f"{'Discovered Subdomain' if is_known else 'Uncataloged Subdomain Asset'}: {sub}",
                        description=f"Passive intelligence revealed active hostname '{sub}' under '{target_domain}'."
                        + (" Not currently registered in asset inventory." if not is_known else ""),
                        evidence=json.dumps({"subdomain": sub, "parent_domain": target_domain}),
                        discovery_source="CERTIFICATE_TRANSPARENCY",
                        first_observed_at=now,
                        last_observed_at=now,
                        current_status="ACTIVE",
                    )
                )

        # 3. Public IP Endpoints
        for ip in dns_data.get("public_ips", []):
            findings.append(
                ExposureFinding(
                    organization_id=organization_id,
                    asset_id=asset_id,
                    job_id=job_id,
                    target=ip,
                    finding_category=FindingCategory.PUBLIC_IP,
                    severity=FindingSeverity.INFO,
                    confidence=FindingConfidence.HIGH,
                    title=f"Routable Public IP Endpoint: {ip}",
                    description=f"Public IPv4/IPv6 address {ip} mapped to domain infrastructure.",
                    evidence=json.dumps({"ip": ip, "target_domain": target_domain}),
                    discovery_source="DNS_RESOLVER",
                    first_observed_at=now,
                    last_observed_at=now,
                    current_status="ACTIVE",
                )
            )

        # 4. Email Security Posture (SPF & DMARC)
        has_spf = bool(dns_data.get("spf_record"))
        has_dmarc = bool(dns_data.get("dmarc_record"))

        if not has_spf:
            findings.append(
                ExposureFinding(
                    organization_id=organization_id,
                    asset_id=asset_id,
                    job_id=job_id,
                    target=target_domain,
                    finding_category=FindingCategory.DNS_CONFIGURATION,
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.HIGH,
                    title="Missing SPF Record (Email Spoofing Risk)",
                    description=f"No Sender Policy Framework (SPF) record found on {target_domain}. Adversaries can forge emails using this domain.",
                    evidence=json.dumps({"domain": target_domain, "checked_records": ["TXT"]}),
                    discovery_source="DNS_RESOLVER",
                    first_observed_at=now,
                    last_observed_at=now,
                    current_status="ACTIVE",
                )
            )

        if not has_dmarc:
            findings.append(
                ExposureFinding(
                    organization_id=organization_id,
                    asset_id=asset_id,
                    job_id=job_id,
                    target=f"_dmarc.{target_domain}",
                    finding_category=FindingCategory.DNS_CONFIGURATION,
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.HIGH,
                    title="Missing DMARC Policy (Brand Impersonation Risk)",
                    description=f"No DMARC policy discovered at _dmarc.{target_domain}. Unauthenticated mail cannot be verified by recipient servers.",
                    evidence=json.dumps({"target": f"_dmarc.{target_domain}", "checked_records": ["TXT"]}),
                    discovery_source="DNS_RESOLVER",
                    first_observed_at=now,
                    last_observed_at=now,
                    current_status="ACTIVE",
                )
            )

        # 5. Wildcard & Expired Certificates
        for cert in certificates:
            if cert.get("is_expired"):
                findings.append(
                    ExposureFinding(
                        organization_id=organization_id,
                        asset_id=asset_id,
                        job_id=job_id,
                        target=cert.get("common_name") or target_domain,
                        finding_category=FindingCategory.CERTIFICATE_EXPOSURE,
                        severity=FindingSeverity.CRITICAL,
                        confidence=FindingConfidence.HIGH,
                        title=f"Expired TLS Certificate: {cert.get('common_name')}",
                        description=f"Observed TLS certificate expired on {cert.get('not_after')}.",
                        evidence=json.dumps({
                            "common_name": cert.get("common_name"),
                            "issuer": cert.get("issuer_name"),
                            "not_after": str(cert.get("not_after")),
                        }),
                        discovery_source="CERTIFICATE_TRANSPARENCY",
                        first_observed_at=now,
                        last_observed_at=now,
                        current_status="ACTIVE",
                    )
                )

            if cert.get("is_wildcard"):
                findings.append(
                    ExposureFinding(
                        organization_id=organization_id,
                        asset_id=asset_id,
                        job_id=job_id,
                        target=cert.get("common_name") or target_domain,
                        finding_category=FindingCategory.CERTIFICATE_EXPOSURE,
                        severity=FindingSeverity.LOW,
                        confidence=FindingConfidence.HIGH,
                        title=f"Wildcard TLS Certificate Detected: {cert.get('common_name')}",
                        description="Wildcard certificate in use. A private key compromise impacts all existing and future subdomains.",
                        evidence=json.dumps({
                            "common_name": cert.get("common_name"),
                            "issuer": cert.get("issuer_name"),
                        }),
                        discovery_source="CERTIFICATE_TRANSPARENCY",
                        first_observed_at=now,
                        last_observed_at=now,
                        current_status="ACTIVE",
                    )
                )

        # 6. Dangling CNAME Takeover Candidates
        for dangling in dns_data.get("dangling_cname_candidates", []):
            findings.append(
                ExposureFinding(
                    organization_id=organization_id,
                    asset_id=asset_id,
                    job_id=job_id,
                    target=dangling,
                    finding_category=FindingCategory.DNS_CONFIGURATION,
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.MEDIUM,
                    title=f"Potential Dangling CNAME / Cloud Takeover: {dangling}",
                    description=f"CNAME alias points to external cloud infrastructure ({dangling}). If the cloud tenant is decommissioned, third parties may claim it.",
                    evidence=json.dumps({"cname_target": dangling, "domain": target_domain}),
                    discovery_source="DNS_RESOLVER",
                    first_observed_at=now,
                    last_observed_at=now,
                    current_status="ACTIVE",
                )
            )

        # 7. Internal IP Leakage in DNS
        for internal_ip in dns_data.get("internal_ips_detected", []):
            findings.append(
                ExposureFinding(
                    organization_id=organization_id,
                    asset_id=asset_id,
                    job_id=job_id,
                    target=internal_ip,
                    finding_category=FindingCategory.DNS_CONFIGURATION,
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.HIGH,
                    title=f"Internal IP Leakage in Public DNS: {internal_ip}",
                    description=f"Public DNS records resolve to non-routable/RFC1918 internal IP {internal_ip}, revealing private network numbering.",
                    evidence=json.dumps({"internal_ip": internal_ip, "domain": target_domain}),
                    discovery_source="DNS_RESOLVER",
                    first_observed_at=now,
                    last_observed_at=now,
                    current_status="ACTIVE",
                )
            )

        return findings
