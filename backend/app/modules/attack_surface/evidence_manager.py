"""
PREVENT-X Evidence Manager
Synthesizes multi-source passive telemetry into categorized, actionable Exposure Findings.
Classifies findings by nature (Observed Fact, Potential Weakness, Verified Issue, Unverified Finding)
and assigns rigorous takeover verification statuses without inventing exploitability.
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
    TakeoverVerificationStatus,
    EvidenceNature,
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

        # ----------------------------------------------------------------------
        # 1. Base Domain Discovery (Observed Fact)
        # ----------------------------------------------------------------------
        findings.append(
            ExposureFinding(
                organization_id=organization_id,
                asset_id=asset_id,
                job_id=job_id,
                target=target_domain,
                finding_category=FindingCategory.ATTACK_SURFACE_EXPOSURE,
                severity=FindingSeverity.INFO,
                confidence=FindingConfidence.HIGH,
                evidence_nature=EvidenceNature.OBSERVED_FACT,
                verification_status=TakeoverVerificationStatus.UNVERIFIED_RESOURCE,
                title=f"Public Perimeter Domain: {target_domain}",
                description=f"Primary domain '{target_domain}' is actively routable on the public web.",
                evidence=json.dumps({
                    "domain": target_domain,
                    "registrar": rdap_data.get("registrar_name") if rdap_data else "Unknown",
                    "public_ips": dns_data.get("public_ips", []),
                    "source": "DNS_RDAP",
                }),
                discovery_source="PASSIVE_RECON",
                first_observed_at=now,
                last_observed_at=now,
                current_status="ACTIVE",
            )
        )

        # ----------------------------------------------------------------------
        # 2. Discovered Subdomains (Observed Fact / Asset Mapping)
        # ----------------------------------------------------------------------
        for sub in discovered_domains:
            if sub != target_domain:
                is_known = sub in known_asset_targets
                findings.append(
                    ExposureFinding(
                        organization_id=organization_id,
                        asset_id=asset_id,
                        job_id=job_id,
                        target=sub,
                        finding_category=FindingCategory.ATTACK_SURFACE_EXPOSURE,
                        severity=FindingSeverity.LOW if is_known else FindingSeverity.MEDIUM,
                        confidence=FindingConfidence.HIGH,
                        evidence_nature=EvidenceNature.OBSERVED_FACT,
                        verification_status=TakeoverVerificationStatus.UNVERIFIED_RESOURCE,
                        title=f"{'Cataloged Subdomain' if is_known else 'Uncataloged External Subdomain'}: {sub}",
                        description=f"Passive Certificate Transparency telemetry observed active hostname '{sub}' under '{target_domain}'."
                        + (" Not currently listed in active managed asset inventory." if not is_known else ""),
                        evidence=json.dumps({"subdomain": sub, "parent_domain": target_domain, "source": "CRT_SH"}),
                        discovery_source="CERTIFICATE_TRANSPARENCY",
                        first_observed_at=now,
                        last_observed_at=now,
                        current_status="ACTIVE",
                    )
                )

        # ----------------------------------------------------------------------
        # 3. Public IP Endpoints (Observed Fact)
        # ----------------------------------------------------------------------
        for ip in dns_data.get("public_ips", []):
            findings.append(
                ExposureFinding(
                    organization_id=organization_id,
                    asset_id=asset_id,
                    job_id=job_id,
                    target=ip,
                    finding_category=FindingCategory.ATTACK_SURFACE_EXPOSURE,
                    severity=FindingSeverity.INFO,
                    confidence=FindingConfidence.HIGH,
                    evidence_nature=EvidenceNature.OBSERVED_FACT,
                    verification_status=TakeoverVerificationStatus.UNVERIFIED_RESOURCE,
                    title=f"Routable Public IP Endpoint: {ip}",
                    description=f"Public IPv4/IPv6 address {ip} mapped to domain perimeter infrastructure.",
                    evidence=json.dumps({"ip": ip, "target_domain": target_domain, "source": "DNS_RESOLVER"}),
                    discovery_source="DNS_RESOLVER",
                    first_observed_at=now,
                    last_observed_at=now,
                    current_status="ACTIVE",
                )
            )

        # ----------------------------------------------------------------------
        # 4. Email Security Posture (SPF & DMARC) (Potential Weakness)
        # ----------------------------------------------------------------------
        has_spf = bool(dns_data.get("spf_record"))
        has_dmarc = bool(dns_data.get("dmarc_record"))

        if not has_spf:
            findings.append(
                ExposureFinding(
                    organization_id=organization_id,
                    asset_id=asset_id,
                    job_id=job_id,
                    target=target_domain,
                    finding_category=FindingCategory.EMAIL_SECURITY_POSTURE,
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.HIGH,
                    evidence_nature=EvidenceNature.POTENTIAL_WEAKNESS,
                    verification_status=TakeoverVerificationStatus.UNVERIFIED_RESOURCE,
                    title="Missing SPF Record (Domain Spoofing Susceptibility)",
                    description=f"No Sender Policy Framework (SPF) record found on {target_domain}. Email receivers cannot verify authorized sending MTAs.",
                    evidence=json.dumps({"domain": target_domain, "query": "TXT", "result": "NO_SPF_RECORD"}),
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
                    finding_category=FindingCategory.EMAIL_SECURITY_POSTURE,
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.HIGH,
                    evidence_nature=EvidenceNature.POTENTIAL_WEAKNESS,
                    verification_status=TakeoverVerificationStatus.UNVERIFIED_RESOURCE,
                    title="Missing DMARC Policy (Brand Impersonation Susceptibility)",
                    description=f"No DMARC enforcement policy discovered at _dmarc.{target_domain}. Unauthenticated outbound email cannot be rejected.",
                    evidence=json.dumps({"target": f"_dmarc.{target_domain}", "query": "TXT", "result": "NO_DMARC_RECORD"}),
                    discovery_source="DNS_RESOLVER",
                    first_observed_at=now,
                    last_observed_at=now,
                    current_status="ACTIVE",
                )
            )

        # ----------------------------------------------------------------------
        # 5. Certificate & TLS Posture (Availability / Architecture)
        # ----------------------------------------------------------------------
        for cert in certificates:
            if cert.get("is_expired"):
                findings.append(
                    ExposureFinding(
                        organization_id=organization_id,
                        asset_id=asset_id,
                        job_id=job_id,
                        target=cert.get("common_name") or target_domain,
                        finding_category=FindingCategory.CERTIFICATE_TLS_POSTURE,
                        severity=FindingSeverity.CRITICAL,
                        confidence=FindingConfidence.HIGH,
                        evidence_nature=EvidenceNature.VERIFIED_ISSUE,
                        verification_status=TakeoverVerificationStatus.UNVERIFIED_RESOURCE,
                        title=f"Expired TLS Certificate: {cert.get('common_name')}",
                        description=f"Observed TLS certificate expired on {cert.get('not_after')}. Users visiting this host face browser security warnings.",
                        evidence=json.dumps({
                            "common_name": cert.get("common_name"),
                            "issuer": cert.get("issuer_name"),
                            "not_after": str(cert.get("not_after")),
                            "source": "CRT_SH",
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
                        finding_category=FindingCategory.CERTIFICATE_TLS_POSTURE,
                        severity=FindingSeverity.LOW,
                        confidence=FindingConfidence.HIGH,
                        evidence_nature=EvidenceNature.POTENTIAL_WEAKNESS,
                        verification_status=TakeoverVerificationStatus.UNVERIFIED_RESOURCE,
                        title=f"Wildcard TLS Scope: {cert.get('common_name')}",
                        description="Wildcard certificate in use. This is an architectural indicator: compromise of the private key expands blast radius across all current and future subdomains.",
                        evidence=json.dumps({
                            "common_name": cert.get("common_name"),
                            "issuer": cert.get("issuer_name"),
                            "is_vulnerability": False,
                        }),
                        discovery_source="CERTIFICATE_TRANSPARENCY",
                        first_observed_at=now,
                        last_observed_at=now,
                        current_status="ACTIVE",
                    )
                )

        # ----------------------------------------------------------------------
        # 6. Resource Takeover Indicators (CNAMEs)
        # ----------------------------------------------------------------------
        cname_status = dns_data.get("cname_takeover_status")
        for dangling in dns_data.get("dangling_cname_candidates", []):
            if cname_status == TakeoverVerificationStatus.CONFIRMED_TAKEOVER:
                v_status = TakeoverVerificationStatus.CONFIRMED_TAKEOVER
                nature = EvidenceNature.VERIFIED_ISSUE
                sev = FindingSeverity.CRITICAL
                conf = FindingConfidence.HIGH
                desc = f"Confirmed unclaimed external cloud tenancy ({dangling}) corroborated by provider error signature and independent verification."
            elif cname_status == TakeoverVerificationStatus.VERIFIED_UNCLAIMED_RESOURCE:
                v_status = TakeoverVerificationStatus.VERIFIED_UNCLAIMED_RESOURCE
                nature = EvidenceNature.VERIFIED_ISSUE
                sev = FindingSeverity.HIGH
                conf = FindingConfidence.HIGH
                desc = f"CNAME alias points to external cloud infrastructure ({dangling}) with confirmed provider-specific unclaimed error signature. Risk of external subdomain takeover."
            elif cname_status == TakeoverVerificationStatus.POTENTIAL_DANGLING_CNAME:
                v_status = TakeoverVerificationStatus.POTENTIAL_DANGLING_CNAME
                nature = EvidenceNature.POTENTIAL_WEAKNESS
                sev = FindingSeverity.MEDIUM
                conf = FindingConfidence.MEDIUM
                desc = f"CNAME alias points to external cloud hosting ({dangling}). DNS or provider indicator detected, but unclaimed status is unconfirmed without signature match."
            else:
                v_status = TakeoverVerificationStatus.UNVERIFIED_RESOURCE
                nature = EvidenceNature.UNVERIFIED_FINDING
                sev = FindingSeverity.LOW
                conf = FindingConfidence.LOW
                desc = f"CNAME alias points to external cloud hosting ({dangling}). Target connectivity or resolution check was inconclusive."

            findings.append(
                ExposureFinding(
                    organization_id=organization_id,
                    asset_id=asset_id,
                    job_id=job_id,
                    target=dangling,
                    finding_category=FindingCategory.RESOURCE_TAKEOVER_INDICATOR,
                    severity=sev,
                    confidence=conf,
                    evidence_nature=nature,
                    verification_status=v_status,
                    title=f"Resource Takeover Indicator: {dangling}",
                    description=desc,
                    evidence=json.dumps({
                        "cname_target": dangling,
                        "domain": target_domain,
                        "verification_status": v_status,
                        "resolution_checked": True,
                    }),
                    discovery_source="DNS_RESOLVER",
                    first_observed_at=now,
                    last_observed_at=now,
                    current_status="ACTIVE",
                )
            )

        # ----------------------------------------------------------------------
        # 7. Internal IP Leakage in DNS (Verified Issue)
        # ----------------------------------------------------------------------
        for internal_ip in dns_data.get("internal_ips_detected", []):
            findings.append(
                ExposureFinding(
                    organization_id=organization_id,
                    asset_id=asset_id,
                    job_id=job_id,
                    target=internal_ip,
                    finding_category=FindingCategory.DNS_CONFIGURATION_WEAKNESS,
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.HIGH,
                    evidence_nature=EvidenceNature.VERIFIED_ISSUE,
                    verification_status=TakeoverVerificationStatus.UNVERIFIED_RESOURCE,
                    title=f"Internal IP Leakage in Public DNS: {internal_ip}",
                    description=f"Public DNS records resolve to non-routable/RFC1918 internal IP {internal_ip}, leaking private network topology.",
                    evidence=json.dumps({"internal_ip": internal_ip, "domain": target_domain, "source": "DNS_RESOLVER"}),
                    discovery_source="DNS_RESOLVER",
                    first_observed_at=now,
                    last_observed_at=now,
                    current_status="ACTIVE",
                )
            )

        return findings
