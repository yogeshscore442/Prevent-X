"""
PREVENT-X Live External Integration Test Suite (Phase 2 Prompt 1.2)
Executes REAL passive queries against external networks without active probing or exploitation.
Tests real DNS resolvers, real RDAP registries, and real Certificate Transparency logs.

DOCUMENTED AUTHORIZATION BASIS:
1. Target: nasscom.in
   - Authorization Source: NASSCOM Problem Statement 5 Partner
     (NASSCOM Applied Research Bridge 2.0: 'AI-Era Virtual Patching for Security Protection of Indian SMBs')
   - Discovery Policy: PUBLIC_PASSIVE
   - Authorized Scope: Apex domain DNS records (A, MX, TXT)
   - Data Source: Public Recursive DNS Resolvers (port 53)
   - Operational Rule: Zero port scanning, zero active HTTP probing, zero authentication attempts.

2. Target: example.com
   - Authorization Source: IETF RFC 2606 & RFC 6761 Reserved Testing & Documentation Domain
     (Permanently designated by IANA/ICANN for non-production software testing and verification)
   - Discovery Policy: PUBLIC_PASSIVE
   - Authorized Scope: Certificate Transparency public logs & ICANN RDAP registry
   - Data Source: crt.sh (Sectigo CT Log Reader) & rdap.org (ICANN RDAP Bootstrap)
   - Operational Rule: Safe, read-only GET requests via SafePinningTransport gate.
"""

import json
import uuid
from datetime import datetime, timezone
import pytest

from backend.app.models.attack_surface import (
    DiscoveryJob,
    DiscoveryJobStatus,
    DiscoveryPolicy,
    FindingCategory,
    DiscoveredDomain,
    DNSRecord,
    ExposureFinding,
)
from backend.app.models.asset import ManagedAsset
from backend.app.modules.attack_surface.adapters.certificate_transparency import CertificateTransparencyAdapter
from backend.app.modules.attack_surface.adapters.dns_intelligence import DNSIntelligenceAdapter
from backend.app.modules.attack_surface.adapters.rdap import RDAPAdapter
from backend.app.modules.attack_surface.discovery_manager import DiscoveryManager
from backend.app.modules.attack_surface.risk_engine import DeterministicRiskEngine


@pytest.mark.live_integration
def test_live_dns_intelligence_nasscom():
    """
    Validates real DNS intelligence collection against nasscom.in.
    Verifies A records, MX records, SPF, and DMARC resolution via public resolvers.
    """
    adapter = DNSIntelligenceAdapter()
    result = adapter.resolve_domain("nasscom.in")

    assert "records" in result
    assert len(result["records"]) > 0

    # Verify public IP resolution
    assert len(result["public_ips"]) > 0
    # Must NOT contain internal IPs
    assert len(result["internal_ips_detected"]) == 0

    # Verify SPF and DMARC records
    assert result["spf_record"] is not None
    assert "v=spf1" in result["spf_record"].lower()
    assert result["dmarc_record"] is not None
    assert "v=dmarc1" in result["dmarc_record"].lower()

    # Verify records have TTL, source, and timestamps
    for rec in result["records"]:
        assert rec["source"] == "DNS_RESOLVER"
        assert rec["resolution_status"] == "RESOLVED"
        assert rec["ttl"] is not None


@pytest.mark.live_integration
def test_live_rdap_registration_profile_example():
    """
    Validates real RDAP domain profile retrieval against example.com.
    Verifies registrar parsing, nameservers, status codes, and PII sanitization.
    """
    adapter = RDAPAdapter()
    profile = adapter.fetch_domain_profile("example.com")

    assert profile is not None
    assert profile["registrar_name"] is not None
    assert "Internet Assigned Numbers Authority" in profile["registrar_name"] or "IANA" in profile["registrar_name"] or "ICANN" in profile["registrar_name"]

    nameservers = json.loads(profile["nameservers"]) if isinstance(profile["nameservers"], str) else profile["nameservers"]
    assert len(nameservers) >= 1

    status_codes = json.loads(profile["status_codes"]) if isinstance(profile["status_codes"], str) else profile["status_codes"]
    assert len(status_codes) >= 1

    # Strict PII verification: Ensure no personal phone/email leaks in sanitized structure
    serialized = json.dumps(profile, default=str)
    assert "@gmail.com" not in serialized
    assert "@yahoo.com" not in serialized


@pytest.mark.live_integration
def test_live_certificate_transparency_example():
    """
    Validates real Certificate Transparency logging against example.com via crt.sh.
    Verifies SAN extraction, subdomain deduplication, and TLS validity computation.
    """
    adapter = CertificateTransparencyAdapter()
    raw_certs = adapter.fetch_certificates("example.com")

    # crt.sh is a free public community service that intermittently experiences 502/503/504 outages
    if not raw_certs:
        pytest.skip("crt.sh upstream service temporarily unavailable or rate-limited (502 Bad Gateway / timeout)")

    assert len(raw_certs) > 0

    parsed_certs, discovered_subdomains = adapter.parse_certificates_and_domains("example.com", raw_certs)
    assert len(parsed_certs) > 0
    assert "example.com" in discovered_subdomains

    # Verify certificate fields
    sample = parsed_certs[0]
    assert "common_name" in sample
    assert "issuer_name" in sample
    assert "serial_number" in sample
    assert "is_expired" in sample
    assert "is_wildcard" in sample
    assert sample["source"] == "CRT_SH"


@pytest.mark.live_integration
def test_live_full_passive_discovery_pipeline(db_session, test_tenants):
    """
    Executes a complete real end-to-end passive discovery job using live adapters
    against an authorized test asset (example.com).
    Verifies database ingestion, deduplication, categorized findings, and normalized risk calculation.
    """
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    asset = ManagedAsset(
        organization_id=org_a.id,
        name="Example Reference Portal",
        asset_type="WEB_APPLICATION",
        target="example.com",
        environment="PRODUCTION",
        criticality="LOW",
        is_in_scope=True,
    )
    db_session.add(asset)
    db_session.commit()

    job = DiscoveryJob(
        organization_id=org_a.id,
        asset_id=asset.id,
        target_domain="example.com",
        discovery_policy=DiscoveryPolicy.PUBLIC_PASSIVE,
        status=DiscoveryJobStatus.QUEUED,
        progress_percent=0,
        current_stage="QUEUED",
        authorized_scope=asset.target,
        initiated_by_user_id=admin_a.id,
        authorization_confirmed=True,
        authorized_at=datetime.now(timezone.utc),
    )
    db_session.add(job)
    db_session.commit()

    # Use live adapters with real network access
    live_manager = DiscoveryManager(
        ct_adapter=CertificateTransparencyAdapter(),
        dns_adapter=DNSIntelligenceAdapter(),
        rdap_adapter=RDAPAdapter(),
        risk_engine=DeterministicRiskEngine(),
    )

    completed_job = live_manager.run_discovery(db_session, job.id)

    assert completed_job.status == DiscoveryJobStatus.COMPLETED
    assert completed_job.progress_percent == 100
    assert completed_job.domains_discovered_count >= 1
    assert completed_job.findings_count > 0
    assert 0.0 <= completed_job.initial_exposure_score <= 100.0

    # Verify discovered domains in PostgreSQL
    domains = db_session.query(DiscoveredDomain).filter(DiscoveredDomain.job_id == job.id).all()
    assert len(domains) >= 1
    domain_names = {d.domain_name for d in domains}
    assert "example.com" in domain_names

    # Verify exposure findings in PostgreSQL
    findings = db_session.query(ExposureFinding).filter(ExposureFinding.job_id == job.id).all()
    assert len(findings) == completed_job.findings_count

    # Check finding categorization
    categories = {f.finding_category for f in findings}
    assert FindingCategory.PUBLIC_DOMAIN in categories or FindingCategory.ATTACK_SURFACE_EXPOSURE in categories

    # Verify that all findings have evidence nature and verification status
    for f in findings:
        assert f.evidence_nature is not None
        assert f.verification_status is not None

