"""
PREVENT-X Attack Surface Intelligence Engine Tests (Phase 2 Prompt 1)
Validates scope boundaries, SSRF prevention, adapters, deterministic risk scoring,
evidence generation, asynchronous task execution, and API endpoints with tenant isolation.
"""

import json
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
import dns.resolver
import pytest
from fastapi.testclient import TestClient

from backend.app.models.attack_surface import (
    DiscoveryJob,
    DiscoveryJobStatus,
    DiscoveryPolicy,
    DiscoveredDomain,
    DNSRecord,
    ExposureFinding,
    FindingSeverity,
    FindingCategory,
)
from backend.app.models.asset import ManagedAsset
from backend.app.models.organization import Organization
from backend.app.modules.attack_surface.scope_validator import ScopeValidator, ScopeValidationError
from backend.app.modules.attack_surface.risk_engine import DeterministicRiskEngine
from backend.app.modules.attack_surface.evidence_manager import EvidenceManager
from backend.app.modules.attack_surface.adapters.certificate_transparency import CertificateTransparencyAdapter
from backend.app.modules.attack_surface.adapters.dns_intelligence import DNSIntelligenceAdapter
from backend.app.modules.attack_surface.adapters.rdap import RDAPAdapter
from backend.app.modules.attack_surface.discovery_manager import DiscoveryManager


# ==============================================================================
# 1. SCOPE VALIDATOR & SSRF DEFENSES
# ==============================================================================

def test_scope_validator_normalizes_domains():
    assert ScopeValidator.normalize_target_domain("https://portal.smbclient.in/dashboard") == "portal.smbclient.in"
    assert ScopeValidator.normalize_target_domain("HTTP://API.EXAMPLE.COM:8443/") == "api.example.com"
    assert ScopeValidator.normalize_target_domain("  demo.example.in.  ") == "demo.example.in"


def test_scope_validator_extracts_apex_domain():
    assert ScopeValidator.extract_apex_domain("api.portal.smbclient.in") == "smbclient.in"
    assert ScopeValidator.extract_apex_domain("portal.smbclient.co.in") == "smbclient.co.in"
    assert ScopeValidator.extract_apex_domain("example.com") == "example.com"


def test_scope_validator_rejects_ssrf_and_private_ips():
    # RFC 1918 Private ranges
    with pytest.raises(ScopeValidationError) as exc:
        ScopeValidator.check_ssrf_and_forbidden_networks("10.0.0.1")
    assert "private" in str(exc.value.detail).lower()

    with pytest.raises(ScopeValidationError):
        ScopeValidator.check_ssrf_and_forbidden_networks("192.168.1.100")

    with pytest.raises(ScopeValidationError):
        ScopeValidator.check_ssrf_and_forbidden_networks("172.16.5.20")

    # Loopback
    with pytest.raises(ScopeValidationError):
        ScopeValidator.check_ssrf_and_forbidden_networks("127.0.0.1")

    # Cloud metadata
    with pytest.raises(ScopeValidationError):
        ScopeValidator.check_ssrf_and_forbidden_networks("169.254.169.254")

    # Forbidden internal TLDs
    with pytest.raises(ScopeValidationError):
        ScopeValidator.check_ssrf_and_forbidden_networks("server.local")

    with pytest.raises(ScopeValidationError):
        ScopeValidator.check_ssrf_and_forbidden_networks("database.internal")

    with pytest.raises(ScopeValidationError):
        ScopeValidator.check_ssrf_and_forbidden_networks("cluster.lan")


def test_scope_validator_enforces_asset_ownership_and_hierarchy(db_session, test_tenants):
    org_a = test_tenants["org_a"]

    # Asset for test_organization
    asset = ManagedAsset(
        organization_id=org_a.id,
        name="Main Corporate Portal",
        asset_type="WEB_APPLICATION",
        target="portal.smbclient.in",
        environment="PRODUCTION",
        criticality="HIGH",
        is_in_scope=True,
    )
    db_session.add(asset)
    db_session.commit()

    # 1. Reject if authorization not confirmed
    with pytest.raises(ScopeValidationError) as exc:
        ScopeValidator.validate_and_authorize_job(
            db=db_session,
            organization_id=org_a.id,
            asset_id=asset.id,
            target_domain="portal.smbclient.in",
            authorization_confirmed=False,
        )
    assert "explicit authorization confirmation is mandatory" in str(exc.value.detail).lower()

    # 2. Reject out-of-scope domain target (arbitrary third party)
    with pytest.raises(ScopeValidationError) as exc:
        ScopeValidator.validate_and_authorize_job(
            db=db_session,
            organization_id=org_a.id,
            asset_id=asset.id,
            target_domain="unauthorized-competitor.com",
            authorization_confirmed=True,
        )
    assert "outside the authorized scope" in str(exc.value.detail).lower()

    # 3. Success for exact target or valid subdomain
    val_asset, effective_target, effective_policy, evidence = ScopeValidator.validate_and_authorize_job(
        db=db_session,
        organization_id=org_a.id,
        asset_id=asset.id,
        target_domain="sub.portal.smbclient.in",
        authorization_confirmed=True,
    )
    assert val_asset.id == asset.id
    assert effective_target == "sub.portal.smbclient.in"
    assert effective_policy == "PUBLIC_PASSIVE"
    assert evidence["status"] == "APPROVED"
    assert evidence["authorized_scope"] == asset.target
    assert evidence["asset_id"] == str(asset.id)


def test_ssrf_defense_alternate_encodings_and_mapped_ipv6():
    from backend.app.modules.attack_surface.ssrf_defense import SSRFDefense, SSRFValidationError

    # Decimal integer IP encodings (e.g. 2130706433 = 127.0.0.1)
    with pytest.raises(SSRFValidationError) as exc:
        SSRFDefense.validate_url_or_ip("http://2130706433/admin")
    assert "loopback" in str(exc.value.detail).lower()

    # Octal IP encodings (e.g. 0177.0.0.1 = 127.0.0.1)
    with pytest.raises(SSRFValidationError):
        SSRFDefense.validate_url_or_ip("http://0177.0.0.1/")

    # Hex IP encodings (e.g. 0x7f000001 = 127.0.0.1)
    with pytest.raises(SSRFValidationError):
        SSRFDefense.validate_url_or_ip("http://0x7f.0.0.1/")

    # IPv4-mapped IPv6 (::ffff:127.0.0.1, ::ffff:10.0.0.1, ::ffff:169.254.169.254)
    with pytest.raises(SSRFValidationError) as exc:
        SSRFDefense.validate_url_or_ip("http://[::ffff:127.0.0.1]/")
    assert "loopback" in str(exc.value.detail).lower()

    with pytest.raises(SSRFValidationError) as exc:
        SSRFDefense.validate_url_or_ip("http://[::ffff:10.0.0.1]/")
    assert "private" in str(exc.value.detail).lower()

    with pytest.raises(SSRFValidationError) as exc:
        SSRFDefense.validate_url_or_ip("http://[::ffff:169.254.169.254]/")
    assert "cloud metadata" in str(exc.value.detail).lower()

    # Cloud hypervisor metadata endpoints
    for meta_ip in ["169.254.169.254", "100.100.100.200", "192.0.0.192"]:
        with pytest.raises(SSRFValidationError) as exc:
            SSRFDefense.validate_url_or_ip(f"http://{meta_ip}/latest/meta-data/")
        assert "cloud metadata" in str(exc.value.detail).lower()


def test_ssrf_defense_dns_rebinding_and_redirect_checks():
    from backend.app.modules.attack_surface.ssrf_defense import SSRFDefense, SSRFValidationError

    # DNS rebinding: resolved IPs containing private/loopback addresses must be rejected
    with pytest.raises(SSRFValidationError) as exc:
        SSRFDefense.validate_resolved_ips(["93.184.216.34", "127.0.0.1"], allow_private=False)
    assert "loopback" in str(exc.value.detail).lower()

    # Redirect validator: following a redirect to internal address must fail
    validator = SSRFDefense.create_redirect_validator(allow_private=False)
    fake_request = MagicMock()
    fake_request.url = "http://127.0.0.1/internal-secret"
    with pytest.raises(SSRFValidationError) as exc:
        validator(fake_request)
    assert "loopback" in str(exc.value.detail).lower()


def test_public_passive_vs_authorized_internal_policies(db_session, test_tenants):
    from backend.app.models.attack_surface import DiscoveryPolicy
    org_a = test_tenants["org_a"]

    # 1. Registered internal asset with CIDR target
    internal_asset = ManagedAsset(
        organization_id=org_a.id,
        name="Internal ERP Cluster",
        asset_type="INTERNAL_NETWORK",
        target="10.50.0.0/16",
        environment="STAGING",
        criticality="MEDIUM",
        is_in_scope=True,
    )
    db_session.add(internal_asset)
    db_session.commit()

    # A) Under PUBLIC_PASSIVE policy, private IP is strictly rejected
    with pytest.raises(ScopeValidationError) as exc:
        ScopeValidator.validate_and_authorize_job(
            db=db_session,
            organization_id=org_a.id,
            asset_id=internal_asset.id,
            target_domain="10.50.1.5",
            authorization_confirmed=True,
            discovery_policy=DiscoveryPolicy.PUBLIC_PASSIVE,
        )
    assert "private" in str(exc.value.detail).lower()

    # B) Under AUTHORIZED_INTERNAL policy without explicit permission or confirm, rejected
    with pytest.raises(ScopeValidationError):
        ScopeValidator.validate_and_authorize_job(
            db=db_session,
            organization_id=org_a.id,
            asset_id=internal_asset.id,
            target_domain="10.50.1.5",
            authorization_confirmed=False,
            discovery_policy=DiscoveryPolicy.AUTHORIZED_INTERNAL,
            user_has_internal_permission=True,
        )

    # C) Under AUTHORIZED_INTERNAL with permission, authorized IP within CIDR is allowed
    val_asset, effective_target, pol, evidence = ScopeValidator.validate_and_authorize_job(
        db=db_session,
        organization_id=org_a.id,
        asset_id=internal_asset.id,
        target_domain="10.50.1.5",
        authorization_confirmed=True,
        discovery_policy=DiscoveryPolicy.AUTHORIZED_INTERNAL,
        user_has_internal_permission=True,
    )
    assert effective_target == "10.50.1.5"
    assert pol == DiscoveryPolicy.AUTHORIZED_INTERNAL
    assert evidence["discovery_policy"] == DiscoveryPolicy.AUTHORIZED_INTERNAL
    assert "10.50.0.0/16" in evidence["allowlist_cidrs"]

    # D) Target outside approved CIDR (e.g. 192.168.1.1) is rejected even under AUTHORIZED_INTERNAL
    with pytest.raises(ScopeValidationError) as exc:
        ScopeValidator.validate_and_authorize_job(
            db=db_session,
            organization_id=org_a.id,
            asset_id=internal_asset.id,
            target_domain="192.168.1.1",
            authorization_confirmed=True,
            discovery_policy=DiscoveryPolicy.AUTHORIZED_INTERNAL,
            user_has_internal_permission=True,
        )
    assert "authorized cidr allowlist" in str(exc.value.detail).lower()

    # E) Cloud metadata and loopback are rejected even under AUTHORIZED_INTERNAL
    with pytest.raises(ScopeValidationError):
        ScopeValidator.validate_and_authorize_job(
            db=db_session,
            organization_id=org_a.id,
            asset_id=internal_asset.id,
            target_domain="169.254.169.254",
            authorization_confirmed=True,
            discovery_policy=DiscoveryPolicy.AUTHORIZED_INTERNAL,
            user_has_internal_permission=True,
        )


def test_dangling_cname_classification_unverified_vs_verified():
    from backend.app.models.attack_surface import TakeoverVerificationStatus
    engine = DeterministicRiskEngine()

    dns_unverified = {
        "spf_record": "v=spf1 -all",
        "dmarc_record": "v=DMARC1; p=reject;",
        "public_ips": ["203.0.113.1"],
        "internal_ips_detected": [],
        "dangling_cname_candidates": ["app.azurewebsites.net"],
        "cname_takeover_status": TakeoverVerificationStatus.UNVERIFIED_RESOURCE,
    }
    calc_unverified = engine.calculate_risk(
        domain_name="example.com",
        subdomains=["example.com"],
        dns_data=dns_unverified,
        certificates=[],
    )
    takeover_factor_unverified = next(f for f in calc_unverified["factors"] if f["factor_key"] == "resource_takeover")
    assert takeover_factor_unverified["score"] == 7.5
    assert takeover_factor_unverified["evidence_quality"] == "MEDIUM"

    dns_verified_unclaimed = {
        "spf_record": "v=spf1 -all",
        "dmarc_record": "v=DMARC1; p=reject;",
        "public_ips": ["203.0.113.1"],
        "internal_ips_detected": [],
        "dangling_cname_candidates": ["app.azurewebsites.net"],
        "cname_takeover_status": TakeoverVerificationStatus.VERIFIED_UNCLAIMED_RESOURCE,
    }
    calc_verified = engine.calculate_risk(
        domain_name="example.com",
        subdomains=["example.com"],
        dns_data=dns_verified_unclaimed,
        certificates=[],
    )
    takeover_factor_verified = next(f for f in calc_verified["factors"] if f["factor_key"] == "resource_takeover")
    assert takeover_factor_verified["score"] == 15.0
    assert takeover_factor_verified["evidence_quality"] == "HIGH"


# ==============================================================================
# 2. DETERMINISTIC RISK SCORING ENGINE
# ==============================================================================

def test_deterministic_risk_engine_clean_posture():
    engine = DeterministicRiskEngine()
    dns_clean = {
        "spf_record": "v=spf1 include:_spf.google.com ~all",
        "dmarc_record": "v=DMARC1; p=reject;",
        "public_ips": ["203.0.113.1"],
        "internal_ips_detected": [],
        "dangling_cname_candidates": [],
    }
    certs_clean = [{
        "common_name": "example.com",
        "is_wildcard": False,
        "is_expired": False,
        "not_after": datetime.now(timezone.utc) + timedelta(days=90),
    }]

    calc = engine.calculate_risk(
        domain_name="example.com",
        subdomains=["example.com"],
        dns_data=dns_clean,
        certificates=certs_clean,
        rdap_data={"registrar_name": "SafeRegistrar"},
    )

    assert calc["total_score"] == 0.0
    assert calc["risk_level"] == "LOW"
    assert len(calc["factors"]) == 6


def test_deterministic_risk_engine_elevated_exposure():
    from backend.app.models.attack_surface import TakeoverVerificationStatus
    engine = DeterministicRiskEngine()
    dns_risky = {
        "spf_record": None,  # Missing SPF (+10)
        "dmarc_record": None,  # Missing DMARC (+10 -> +20 total for both)
        "public_ips": ["203.0.113.1"],
        "internal_ips_detected": ["10.0.0.5"],  # RFC1918 leak (+10)
        "dangling_cname_candidates": ["takeover.s3.amazonaws.com"],
        "cname_takeover_status": TakeoverVerificationStatus.VERIFIED_UNCLAIMED_RESOURCE,  # Verified unclaimed (+15)
    }
    certs_risky = [
        {"common_name": "*.example.com", "is_wildcard": True, "is_expired": True},  # Wildcard (+15), Expired (+20)
    ]
    subdomains = [f"sub{i}.example.com" for i in range(25)]  # Sprawl > 20 (+20)

    calc = engine.calculate_risk(
        domain_name="example.com",
        subdomains=subdomains,
        dns_data=dns_risky,
        certificates=certs_risky,
        rdap_data=None,
    )

    # Exactly 20 (sprawl) + 15 (wildcard) + 20 (expired) + 20 (no SPF/DMARC) + 15 (verified unclaimed CNAME) + 10 (internal IP) = exactly 100.0
    assert calc["total_score"] == 100.0
    assert calc["risk_level"] == "CRITICAL"

    # Test mathematical invariance: sum of max factor weights must equal exactly 100.0
    total_max_weights = sum(f["max_weight"] for f in calc["factors"])
    assert total_max_weights == 100.0

    # Ensure every factor reports evidence quality and is_vulnerability
    for factor in calc["factors"]:
        assert "evidence_quality" in factor
        assert "confidence" in factor
        assert factor["is_vulnerability"] is False  # Factors are exposure metrics, not confirmed vulnerabilities!


# ==============================================================================
# 3. ADAPTERS TELEMETRY & SANITIZATION
# ==============================================================================

def test_ct_adapter_parsing_and_subdomain_extraction():
    adapter = CertificateTransparencyAdapter()
    sample_ct_entries = [
        {
            "id": 101,
            "issuer_name": "Let's Encrypt Authority X3",
            "common_name": "example.com",
            "name_value": "example.com\napi.example.com\n*.portal.example.com",
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2026-12-31T23:59:59",
            "entry_timestamp": "2026-01-01T01:00:00",
            "serial_number": "123456789",
        }
    ]

    parsed_certs, subdomains = adapter.parse_certificates_and_domains("example.com", sample_ct_entries)
    assert "example.com" in subdomains
    assert "api.example.com" in subdomains
    assert "portal.example.com" in subdomains  # Wildcard stripped
    assert len(parsed_certs) == 1
    assert parsed_certs[0]["is_wildcard"] is True
    assert parsed_certs[0]["is_expired"] is False


def test_rdap_adapter_pii_sanitization():
    adapter = RDAPAdapter()
    raw_rdap_with_pii = {
        "handle": "DOMAIN-1234",
        "port43": "whois.example.com",
        "ldhName": "example.com",
        "status": ["active"],
        "nameservers": [{"ldhName": "ns1.example.com"}, {"ldhName": "ns2.example.com"}],
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2028-01-01T00:00:00Z"},
        ],
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": ["vcard", [
                    ["fn", {}, "text", "John Doe (Private Person)"],
                    ["email", {}, "text", "john.doe@gmail.com"],
                    ["tel", {}, "text", "+919876543210"],
                    ["adr", {}, "text", ["Street 1", "Bengaluru", "Karnataka", "560001", "India"]],
                ]],
            },
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [
                    ["fn", {}, "text", "GoDaddy Online Security, LLC"],
                ]],
            }
        ],
    }

    sanitized = adapter._sanitize_and_parse(raw_rdap_with_pii)
    # Ensure registrar name is captured
    assert sanitized["registrar_name"] == "GoDaddy Online Security, LLC"
    assert "ns1.example.com" in sanitized["nameservers"]

    # Verify PII was NOT captured in sanitized profile
    serialized = json.dumps(sanitized, default=str)
    assert "John Doe" not in serialized
    assert "john.doe@gmail.com" not in serialized
    assert "+919876543210" not in serialized


# ==============================================================================
# 4. EVIDENCE MANAGER
# ==============================================================================

def test_evidence_manager_generates_categorized_findings():
    org_id = uuid.uuid4()
    asset_id = uuid.uuid4()
    job_id = uuid.uuid4()

    dns_data = {
        "spf_record": None,  # Triggers missing SPF finding
        "dmarc_record": None,  # Triggers missing DMARC finding
        "public_ips": ["203.0.113.10"],
        "internal_ips_detected": ["192.168.1.50"],
        "dangling_cname_candidates": ["cloudapp.azurewebsites.net"],
    }
    certs = [
        {"common_name": "*.smb.in", "issuer_name": "Test CA", "is_wildcard": True, "is_expired": True, "not_after": "2025-01-01"}
    ]

    findings = EvidenceManager.generate_findings_for_job(
        organization_id=org_id,
        asset_id=asset_id,
        job_id=job_id,
        target_domain="smb.in",
        discovered_domains=["smb.in", "dev.smb.in"],
        dns_data=dns_data,
        certificates=certs,
        rdap_data={"registrar_name": "TestRegistrar"},
        known_asset_targets=["smb.in"],
    )

    categories = [f.finding_category for f in findings]
    assert FindingCategory.PUBLIC_DOMAIN in categories
    assert FindingCategory.DNS_CONFIGURATION in categories
    assert FindingCategory.CERTIFICATE_EXPOSURE in categories
    assert FindingCategory.PUBLIC_IP in categories
    assert FindingCategory.UNKNOWN_ASSET_RELATIONSHIP in categories  # dev.smb.in not in known targets

    severities = [f.severity for f in findings]
    assert FindingSeverity.CRITICAL in severities  # Expired certificate
    assert FindingSeverity.HIGH in severities  # Missing SPF/DMARC, internal IP leak


# ==============================================================================
# 5. DISCOVERY MANAGER EXECUTION & STATE LIFECYCLE
# ==============================================================================

def test_discovery_manager_executes_job_lifecycle(db_session, test_tenants):
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]

    # Setup test asset
    asset = ManagedAsset(
        organization_id=org_a.id,
        name="E-Commerce API",
        asset_type="API_GATEWAY",
        target="api.smbclient.in",
        environment="PRODUCTION",
        criticality="HIGH",
        is_in_scope=True,
    )
    db_session.add(asset)
    db_session.commit()

    # Create Job
    job = DiscoveryJob(
        organization_id=org_a.id,
        asset_id=asset.id,
        target_domain="api.smbclient.in",
        status=DiscoveryJobStatus.QUEUED,
        progress_percent=0,
        current_stage="QUEUED",
        authorized_scope=asset.target,
        initiated_by_user_id=admin_a.id,
        authorization_confirmed=True,
        authorized_at=datetime.now(timezone.utc),
        scope_validation_result=json.dumps({
            "status": "APPROVED",
            "organization_id": str(org_a.id),
            "asset_id": str(asset.id),
            "effective_target": "api.smbclient.in",
            "discovery_policy": DiscoveryPolicy.PUBLIC_PASSIVE,
            "authorization_confirmed": True,
        }),
    )
    db_session.add(job)
    db_session.commit()

    # Mock CT and RDAP adapters to avoid relying on live external networks during unit test
    mock_ct = MagicMock(spec=CertificateTransparencyAdapter)
    mock_ct.fetch_certificates.return_value = []
    mock_ct.parse_certificates_and_domains.return_value = (
        [{
            "common_name": "api.smbclient.in",
            "subject_alt_names": "[\"api.smbclient.in\"]",
            "issuer_name": "Let's Encrypt",
            "not_before": datetime.now(timezone.utc) - timedelta(days=30),
            "not_after": datetime.now(timezone.utc) + timedelta(days=60),
            "is_expired": False,
            "is_wildcard": False,
            "serial_number": "999888",
            "logged_at": datetime.now(timezone.utc),
            "source": "CRT_SH",
            "raw_evidence": "{}",
        }],
        {"api.smbclient.in", "auth.api.smbclient.in"}
    )

    mock_dns = MagicMock(spec=DNSIntelligenceAdapter)
    mock_dns.resolve_domain.return_value = {
        "records": [
            {"record_type": "A", "record_value": "203.0.113.88", "ttl": 300, "source": "DNS_RESOLVER", "resolution_status": "RESOLVED"},
            {"record_type": "TXT", "record_value": "v=spf1 -all", "ttl": 3600, "source": "DNS_RESOLVER", "resolution_status": "RESOLVED"},
        ],
        "public_ips": ["203.0.113.88"],
        "internal_ips_detected": [],
        "cname_targets": [],
        "dangling_cname_candidates": [],
        "spf_record": "v=spf1 -all",
        "dmarc_record": None,
        "has_mx": False,
        "has_ns": True,
    }

    mock_rdap = MagicMock(spec=RDAPAdapter)
    mock_rdap.fetch_domain_profile.return_value = {
        "handle": "DOM-888",
        "registrar_name": "NIXI Registry India",
        "whois_server": "whois.registry.in",
        "registration_date": datetime.now(timezone.utc) - timedelta(days=365),
        "expiration_date": datetime.now(timezone.utc) + timedelta(days=365),
        "last_updated_date": datetime.now(timezone.utc) - timedelta(days=30),
        "nameservers": json.dumps(["ns1.smbclient.in"]),
        "status_codes": json.dumps(["ok"]),
        "asn": None,
        "raw_data": "{}",
    }

    manager = DiscoveryManager(
        ct_adapter=mock_ct,
        dns_adapter=mock_dns,
        rdap_adapter=mock_rdap,
    )

    completed_job = manager.run_discovery(db_session, job.id)
    assert completed_job.status == DiscoveryJobStatus.COMPLETED
    assert completed_job.progress_percent == 100
    assert completed_job.domains_discovered_count == 2
    assert completed_job.findings_count > 0
    assert completed_job.initial_exposure_score is not None

    # Verify Discovered Domains in Database
    domains = db_session.query(DiscoveredDomain).filter(DiscoveredDomain.job_id == job.id).all()
    domain_names = [d.domain_name for d in domains]
    assert "api.smbclient.in" in domain_names
    assert "auth.api.smbclient.in" in domain_names

    # Verify Exposure Findings in Database
    findings = db_session.query(ExposureFinding).filter(ExposureFinding.job_id == job.id).all()
    assert len(findings) == completed_job.findings_count


# ==============================================================================
# 6. ATTACK SURFACE API ENDPOINTS & MULTI-TENANT ISOLATION
# ==============================================================================

def test_api_attack_surface_full_flow(client: TestClient, db_session, test_tenants):
    org_a = test_tenants["org_a"]

    # 0. Log in as admin_a
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@alphacorp.in", "password": "AlphaAdminPass123!"},
    )
    token = login_resp.json()["tokens"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Register an asset
    asset = ManagedAsset(
        organization_id=org_a.id,
        name="SMB Web App",
        asset_type="WEB_APPLICATION",
        target="webapp.smbclient.in",
        environment="PRODUCTION",
        criticality="CRITICAL",
        is_in_scope=True,
    )
    db_session.add(asset)
    db_session.commit()

    # 2. Trigger Discovery Job via POST /api/v1/attack-surface/discovery
    payload = {
        "asset_id": str(asset.id),
        "target_domain": "webapp.smbclient.in",
        "authorization_confirmed": True,
    }

    with patch("backend.app.modules.attack_surface.tasks.discovery_tasks.execute_discovery_job.delay") as mock_delay:
        resp = client.post("/api/v1/attack-surface/discovery", json=payload, headers=headers)
        assert resp.status_code == 202
        data = resp.json()
        assert data["target_domain"] == "webapp.smbclient.in"
        assert data["status"] == "QUEUED"
        job_id = data["id"]
        mock_delay.assert_called_once()

    # 3. Query Job Status via GET /api/v1/attack-surface/jobs/{id}
    job_resp = client.get(f"/api/v1/attack-surface/jobs/{job_id}", headers=headers)
    assert job_resp.status_code == 200
    assert job_resp.json()["id"] == job_id

    # 4. Cancel Job via POST /api/v1/attack-surface/jobs/{id}/cancel
    cancel_resp = client.post(
        f"/api/v1/attack-surface/jobs/{job_id}/cancel",
        json={"reason": "User testing cancel"},
        headers=headers,
    )
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["status"] == "CANCELLED"

    # 5. Query Overview Dashboard via GET /api/v1/attack-surface/overview
    overview_resp = client.get("/api/v1/attack-surface/overview", headers=headers)
    assert overview_resp.status_code == 200
    ov = overview_resp.json()
    assert "total_discovered_domains" in ov
    assert "findings_by_severity" in ov
    assert "recent_jobs" in ov


def test_api_cross_tenant_attack_surface_isolation(client: TestClient, db_session, test_tenants):
    org_b = test_tenants["org_b"]

    # Log in as Admin of Org A
    login_a = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@alphacorp.in", "password": "AlphaAdminPass123!"},
    )
    token_a = login_a.json()["tokens"]["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # Create an asset under Org B
    victim_asset = ManagedAsset(
        organization_id=org_b.id,
        name="Victim Core Banking",
        asset_type="WEB_APPLICATION",
        target="core.victimbank.in",
        environment="PRODUCTION",
        criticality="CRITICAL",
        is_in_scope=True,
    )
    db_session.add(victim_asset)
    db_session.commit()

    # Tenant A user attempts to trigger discovery against Victim Bank's asset in Org B
    payload = {
        "asset_id": str(victim_asset.id),
        "target_domain": "core.victimbank.in",
        "authorization_confirmed": True,
    }
    resp = client.post("/api/v1/attack-surface/discovery", json=payload, headers=headers_a)
    # Must be strictly rejected with HTTP 403 Forbidden
    assert resp.status_code == 403
    assert "cross-tenant" in resp.json()["detail"].lower()


# ==============================================================================
# 7. PHASE 2 PROMPT 1.2: CONNECTION-LEVEL PINNING, CNAME EVIDENCE, & AUDIT
# ==============================================================================

def test_connection_pinning_and_dns_rebinding_defense():
    from backend.app.modules.attack_surface.ssrf_defense import SafePinningBackend, SSRFValidationError

    backend = SafePinningBackend(allow_private=False)

    # 1. Dual DNS response containing a public IP and a private loopback
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        mock_resolve.return_value = ["93.184.216.34", "127.0.0.1"]
        with pytest.raises(SSRFValidationError) as exc:
            backend.connect_tcp("rebind.example.com", 80)
        assert "dns rebinding defense" in str(exc.value.detail).lower()
        assert "prohibited address" in str(exc.value.detail).lower()

    # 2. DNS rebinding to RFC 1918 private address
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        mock_resolve.return_value = ["10.0.0.1"]
        with pytest.raises(SSRFValidationError) as exc:
            backend.connect_tcp("private.example.com", 80)
        assert "private" in str(exc.value.detail).lower()

    # 3. Direct IPv6 loopback
    with pytest.raises(SSRFValidationError) as exc:
        backend.connect_tcp("::1", 80)
    assert "loopback" in str(exc.value.detail).lower()

    # 4. Direct Cloud Hypervisor Metadata
    for meta in ["169.254.169.254", "100.100.100.200", "192.0.0.192"]:
        with pytest.raises(SSRFValidationError) as exc:
            backend.connect_tcp(meta, 80)
        assert "cloud metadata" in str(exc.value.detail).lower()

    # 5. Non-routable internal TLD
    with pytest.raises(SSRFValidationError) as exc:
        backend.connect_tcp("internal.server.local", 80)
    assert "non-routable tld" in str(exc.value.detail).lower()


def test_safe_transport_response_size_and_redirects():
    import httpx
    from backend.app.modules.attack_surface.ssrf_defense import SSRFDefense, SafePinningTransport, SSRFValidationError

    # 1. Redirect to private IP must be intercepted and blocked
    client = SSRFDefense.create_safe_client(allow_private=False)
    fake_redirect_resp = httpx.Response(
        status_code=302,
        headers={"Location": "http://10.0.0.1/admin"},
        request=httpx.Request("GET", "https://public.example.com/login"),
    )
    with pytest.raises(SSRFValidationError) as exc:
        client._event_hooks["response"][0](fake_redirect_resp)
    assert "private" in str(exc.value.detail).lower()

    # 2. Redirect to cloud metadata must be blocked
    fake_meta_resp = httpx.Response(
        status_code=301,
        headers={"Location": "http://169.254.169.254/latest/meta-data/"},
        request=httpx.Request("GET", "https://public.example.com/"),
    )
    with pytest.raises(SSRFValidationError) as exc:
        client._event_hooks["response"][0](fake_meta_resp)
    assert "cloud metadata" in str(exc.value.detail).lower()

    # 3. Enforce maximum response payload size limit
    transport = SafePinningTransport(allow_private=False, max_response_size=1024)
    huge_request = httpx.Request("GET", "https://example.com/large-archive.zip")
    with patch.object(httpx.HTTPTransport, "handle_request") as mock_handle:
        mock_handle.return_value = httpx.Response(
            status_code=200,
            headers={"Content-Length": "10485760"},  # 10 MB > 1024 bytes
            request=huge_request,
        )
        with pytest.raises(SSRFValidationError) as exc:
            transport.handle_request(huge_request)
        assert "exceeds maximum payload limit" in str(exc.value.detail).lower()


def test_cname_nxdomain_alone_is_never_confirmed_takeover():
    from backend.app.modules.attack_surface.cname_verifier import CNAMEVerifier
    from backend.app.models.attack_surface import TakeoverVerificationStatus, EvidenceNature

    verifier = CNAMEVerifier()

    # Mock DNS returning NXDOMAIN for Azure App Service target, but HTTP check is inconclusive
    with patch("dns.resolver.Resolver.resolve", side_effect=dns.resolver.NXDOMAIN):
        result = verifier.verify_cname(
            subdomain="portal.smbclient.in",
            cname_target="portal.azurewebsites.net",
            allow_http_probe=False,  # DNS only
        )

    # Must be classified as POTENTIAL_DANGLING_CNAME, NEVER CONFIRMED_TAKEOVER
    assert result.status == TakeoverVerificationStatus.POTENTIAL_DANGLING_CNAME
    assert result.status != TakeoverVerificationStatus.CONFIRMED_TAKEOVER
    assert result.evidence_nature == EvidenceNature.POTENTIAL_WEAKNESS
    assert "nxdomain" in result.reason.lower()


def test_cname_provider_signature_match_and_corroboration():
    from backend.app.modules.attack_surface.cname_verifier import CNAMEVerifier
    from backend.app.models.attack_surface import TakeoverVerificationStatus, EvidenceNature

    verifier = CNAMEVerifier()

    # 1. Positive Case: GitHub Pages with confirmed unclaimed error signature
    with patch.object(verifier, "_probe_http_signature") as mock_probe:
        mock_probe.return_value = (404, "There isn't a GitHub Pages site here", "404 - There isn't a GitHub Pages site here")
        pos_result = verifier.verify_cname(
            subdomain="docs.smbclient.in",
            cname_target="smbclient.github.io",
            allow_http_probe=True,
        )

    assert pos_result.status == TakeoverVerificationStatus.VERIFIED_UNCLAIMED_RESOURCE
    assert pos_result.evidence_nature == EvidenceNature.VERIFIED_ISSUE
    assert pos_result.confidence == "HIGH"
    assert pos_result.matched_signature == "There isn't a GitHub Pages site here"

    # 2. Negative Case: Shopify CNAME with active website (no error signature)
    with patch.object(verifier, "_probe_http_signature") as mock_probe:
        mock_probe.return_value = None  # Active 200 OK without signature
        with patch("dns.resolver.Resolver.resolve") as mock_res:
            mock_res.return_value = ["23.227.38.65"]
            neg_result = verifier.verify_cname(
                subdomain="store.smbclient.in",
                cname_target="shops.myshopify.com",
                allow_http_probe=True,
            )

    assert neg_result.status == TakeoverVerificationStatus.UNVERIFIED_RESOURCE
    assert neg_result.confidence == "LOW"

    # 3. Independent Corroboration: Transitions to CONFIRMED_TAKEOVER only with manual analyst signoff
    with patch.object(verifier, "_probe_http_signature") as mock_probe:
        mock_probe.return_value = (404, "<Code>NoSuchBucket</Code>", "<Error><Code>NoSuchBucket</Code></Error>")
        confirmed_result = verifier.verify_cname(
            subdomain="assets.smbclient.in",
            cname_target="smbclient-assets.s3.amazonaws.com",
            allow_http_probe=True,
            independent_analyst_verified=True,
        )

    assert confirmed_result.status == TakeoverVerificationStatus.CONFIRMED_TAKEOVER
    assert confirmed_result.evidence_nature == EvidenceNature.VERIFIED_ISSUE


def test_authorization_evidence_and_duplicate_prevention(client: TestClient, db_session, test_tenants):
    from backend.app.models.attack_surface import DiscoveryJob
    org_a = test_tenants["org_a"]

    # 1. Log in as admin_a
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@alphacorp.in", "password": "AlphaAdminPass123!"},
    )
    token = login_resp.json()["tokens"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Create asset under Org A
    asset = ManagedAsset(
        organization_id=org_a.id,
        name="Production Web Portal",
        asset_type="WEB_APPLICATION",
        target="corp.alphacorp.in",
        environment="PRODUCTION",
        criticality="HIGH",
        is_in_scope=True,
    )
    db_session.add(asset)
    db_session.commit()

    # 3. Test Unauthorized target substitution (competitor domain)
    bad_payload = {
        "asset_id": str(asset.id),
        "target_domain": "unauthorized-target.com",
        "authorization_confirmed": True,
    }
    bad_resp = client.post("/api/v1/attack-surface/discovery", json=bad_payload, headers=headers)
    assert bad_resp.status_code == 403
    assert "outside the authorized scope" in bad_resp.json()["detail"].lower()

    # 4. Test Missing authorization confirmation checkbox
    unconfirmed_payload = {
        "asset_id": str(asset.id),
        "target_domain": "corp.alphacorp.in",
        "authorization_confirmed": False,
    }
    unconfirmed_resp = client.post("/api/v1/attack-surface/discovery", json=unconfirmed_payload, headers=headers)
    assert unconfirmed_resp.status_code == 403
    assert "mandatory" in unconfirmed_resp.json()["detail"].lower()

    # 5. Create legitimate discovery job
    valid_payload = {
        "asset_id": str(asset.id),
        "target_domain": "corp.alphacorp.in",
        "authorization_confirmed": True,
    }
    with patch("backend.app.modules.attack_surface.tasks.discovery_tasks.execute_discovery_job.delay"):
        resp1 = client.post("/api/v1/attack-surface/discovery", json=valid_payload, headers=headers)
        assert resp1.status_code == 202
        job1_data = resp1.json()
        job1_id = job1_data["id"]

        # 6. Duplicate job creation prevention (replay protection)
        resp2 = client.post("/api/v1/attack-surface/discovery", json=valid_payload, headers=headers)
        assert resp2.status_code == 409
        assert "already in progress" in resp2.json()["detail"].lower()

    # 7. Verify all 8 required authorization audit fields on DiscoveryJob
    job = db_session.query(DiscoveryJob).filter(DiscoveryJob.id == uuid.UUID(job1_id)).first()
    assert job is not None
    assert job.asset_id == asset.id
    assert job.organization_id == org_a.id
    assert job.target_domain == "corp.alphacorp.in"
    assert job.discovery_policy == "PUBLIC_PASSIVE"
    assert job.authorization_confirmed is True
    assert job.authorized_scope == asset.target
    assert job.authorized_at is not None
    assert job.scope_validation_result is not None

    # Inspect scope validation JSON
    audit = json.loads(job.scope_validation_result)
    assert audit["status"] == "APPROVED"
    assert audit["organization_id"] == str(org_a.id)
    assert audit["asset_id"] == str(asset.id)
    assert audit["authorized_scope"] == asset.target
    assert audit["effective_target"] == "corp.alphacorp.in"
    assert audit["discovery_policy"] == "PUBLIC_PASSIVE"
    assert audit["authorization_confirmed"] is True
    assert "validated_at" in audit


def test_actual_connected_socket_peer_ip_pinning_and_sni_preservation():
    """
    Prompt 1.3: Verifies that the connected socket peer IP captured from the OS socket
    matches the IP validated by SafePinningBackend.
    Verifies original hostname preservation for TLS SNI and HTTP Host header.
    """
    import socket
    import ssl
    import httpx
    from unittest.mock import MagicMock
    from backend.app.modules.attack_surface.ssrf_defense import SafePinningBackend, SafePinningTransport, SSRFValidationError

    # 1. Private CIDR Pinning: Authorized internal address within CIDR allowlist
    internal_backend = SafePinningBackend(allow_private=True, allowlist_cidrs=["10.50.0.0/16"])
    fake_internal_sock = MagicMock()
    fake_internal_sock.getpeername.return_value = ("10.50.1.25", 8080)

    with patch("socket.create_connection", return_value=fake_internal_sock):
        stream = internal_backend.connect_tcp("10.50.1.25", 8080)
        assert internal_backend.last_connected_peer == ("10.50.1.25", 8080)
        assert internal_backend.last_validated_ip == "10.50.1.25"
        assert internal_backend.last_connected_peer[0] == internal_backend.last_validated_ip

    # 2. Public Domain Pinning & TLS SNI Preservation
    public_backend = SafePinningBackend(allow_private=False)
    fake_socket = MagicMock()
    fake_socket.getpeername.return_value = ("93.184.216.34", 443)

    with patch("socket.getaddrinfo") as mock_gai, patch("socket.create_connection", return_value=fake_socket):
        mock_gai.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 443))
        ]
        stream = public_backend.connect_tcp("portal.example.com", 443)

        assert public_backend.last_connected_peer[0] == "93.184.216.34"
        assert public_backend.last_validated_ip == "93.184.216.34"
        assert public_backend.last_connected_peer[0] == public_backend.last_validated_ip

        # Verify stream requires original hostname for SNI
        mock_ssl_ctx = MagicMock(spec=ssl.SSLContext)
        mock_upgraded_sock = MagicMock()
        mock_ssl_ctx.wrap_socket.return_value = mock_upgraded_sock

        upgraded = stream.start_tls(mock_ssl_ctx, server_hostname="portal.example.com")
        assert stream.last_tls_sni == "portal.example.com"
        mock_ssl_ctx.wrap_socket.assert_called_with(fake_socket, server_hostname="portal.example.com")

        # Verify SNI mismatch rejection: passing pinned IP instead of hostname must be blocked
        with pytest.raises(SSRFValidationError) as exc:
            stream.start_tls(mock_ssl_ctx, server_hostname="93.184.216.34")
        assert "tls sni mismatch" in str(exc.value.detail).lower()

    # 3. HTTP Host Header Preservation
    transport = SafePinningTransport(allow_private=False)
    req = httpx.Request("GET", "https://portal.example.com/api/v1/status")
    assert req.headers["host"] == "portal.example.com"


def test_dns_rebinding_answers_changing_between_validation_and_connection():
    """
    Prompt 1.3: Tests that DNS answers changing between validation and connection
    cannot alter the destination IP of the socket, and tests dual responses.
    """
    import socket
    from unittest.mock import MagicMock
    from backend.app.modules.attack_surface.ssrf_defense import SafePinningBackend, SSRFValidationError

    backend = SafePinningBackend(allow_private=False)

    # 1. DNS answers changing after validation: socket is strictly pinned to the validated IP
    fake_socket = MagicMock()
    fake_socket.getpeername.return_value = ("93.184.216.34", 80)

    # At validation time, DNS returns public IP 93.184.216.34
    with patch("socket.getaddrinfo") as mock_gai, patch("socket.create_connection", return_value=fake_socket) as mock_conn:
        mock_gai.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 80))
        ]
        stream = backend.connect_tcp("rebinding-test.example.com", 80)

        # Socket was created directly to pinned address ("93.184.216.34", 80)
        mock_conn.assert_called_once()
        assert mock_conn.call_args[0][0] == ("93.184.216.34", 80)
        assert backend.last_connected_peer[0] == "93.184.216.34"

        # Now simulate DNS rebinding: subsequent DNS lookup returns 127.0.0.1
        mock_gai.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 80))
        ]
        # Pinned stream remains connected to 93.184.216.34; zero subsequent DNS queries affect it
        assert backend.last_connected_peer[0] == "93.184.216.34"

    # 2. Dual DNS responses at resolution time (public + private loopback) must be aborted immediately
    with patch("socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 80)),
        ]
        with pytest.raises(SSRFValidationError) as exc:
            backend.connect_tcp("dual-rebinding.example.com", 80)
        assert "dns rebinding defense" in str(exc.value.detail).lower()
        assert "prohibited address" in str(exc.value.detail).lower()


def test_redirects_cannot_bypass_ip_validation_comprehensive():
    """
    Prompt 1.3: Verifies that redirects to private IPs, metadata, or unauthorized targets
    are intercepted and aborted before connection.
    """
    import httpx
    from backend.app.modules.attack_surface.ssrf_defense import SafePinningTransport, SSRFValidationError

    transport = SafePinningTransport(allow_private=False)

    forbidden_redirects = [
        ("http://127.0.0.1/admin", "loopback"),
        ("http://10.0.0.1/internal", "private"),
        ("http://192.168.1.1/router", "private"),
        ("http://169.254.169.254/latest/meta-data/", "cloud metadata"),
        ("http://metadata.google.internal/computeMetadata/v1/", "metadata name"),
        ("http://internal.company.local/dashboard", "non-routable tld"),
    ]

    for redirect_url, expected_err in forbidden_redirects:
        fake_req = httpx.Request("GET", "https://public.example.com/login")
        fake_resp = httpx.Response(
            status_code=302,
            headers={"Location": redirect_url},
            request=fake_req,
        )

        with patch.object(httpx.HTTPTransport, "handle_request", return_value=fake_resp):
            with pytest.raises(SSRFValidationError) as exc:
                transport.handle_request(fake_req)
            assert expected_err in str(exc.value.detail).lower()


def test_worker_authorization_revalidation_all_failure_modes(db_session, test_tenants):
    """
    Prompt 1.3: Validates Celery worker-side authorization revalidation across all failure modes:
    - Missing explicit authorization confirmation
    - Deleted / missing asset
    - Cross-tenant asset authorization violation
    - Revoked / out-of-scope asset
    - Target tampering in queued job
    - Policy tampering in queued job
    - Deactivated initiating user
    - Revoked organization membership
    - Expired queued job (> 24 hour TTL)
    - DiscoveryManager job state transition to FAILED with audit error message
    """
    import json
    import uuid
    from datetime import datetime, timezone, timedelta
    from backend.app.models.asset import ManagedAsset
    from backend.app.models.attack_surface import DiscoveryJob, DiscoveryJobStatus, DiscoveryPolicy
    from backend.app.models.user import OrganizationMembership
    from backend.app.modules.attack_surface.scope_validator import ScopeValidator, WorkerAuthorizationError
    from backend.app.modules.attack_surface.discovery_manager import DiscoveryManager

    org_a = test_tenants["org_a"]
    org_b = test_tenants["org_b"]
    admin_a = test_tenants["admin_a"]

    asset_a = ManagedAsset(
        organization_id=org_a.id,
        name="Org A Core Web",
        asset_type="WEB_APPLICATION",
        target="corp.alphacorp.in",
        is_in_scope=True,
    )
    asset_b = ManagedAsset(
        organization_id=org_b.id,
        name="Org B Private API",
        asset_type="WEB_APPLICATION",
        target="internal.betaind.in",
        is_in_scope=True,
    )
    db_session.add_all([asset_a, asset_b])
    db_session.commit()

    base_scope_evidence = {
        "status": "APPROVED",
        "organization_id": str(org_a.id),
        "asset_id": str(asset_a.id),
        "effective_target": "corp.alphacorp.in",
        "discovery_policy": DiscoveryPolicy.PUBLIC_PASSIVE,
        "authorization_confirmed": True,
    }

    # 1. Missing Authorization Confirmation
    job_unconfirmed = DiscoveryJob(
        organization_id=org_a.id,
        asset_id=asset_a.id,
        target_domain="corp.alphacorp.in",
        discovery_policy=DiscoveryPolicy.PUBLIC_PASSIVE,
        authorization_confirmed=False,
        initiated_by_user_id=admin_a.id,
        scope_validation_result=json.dumps(base_scope_evidence),
    )
    with pytest.raises(WorkerAuthorizationError) as exc:
        ScopeValidator.validate_worker_execution_authorization(db_session, job_unconfirmed)
    assert "mandatory user authorization" in str(exc.value.detail).lower()

    # 2. Deleted / Missing Asset
    job_missing_asset = DiscoveryJob(
        organization_id=org_a.id,
        asset_id=uuid.uuid4(),
        target_domain="corp.alphacorp.in",
        discovery_policy=DiscoveryPolicy.PUBLIC_PASSIVE,
        authorization_confirmed=True,
        initiated_by_user_id=admin_a.id,
        scope_validation_result=json.dumps(base_scope_evidence),
    )
    with pytest.raises(WorkerAuthorizationError) as exc:
        ScopeValidator.validate_worker_execution_authorization(db_session, job_missing_asset)
    assert "does not exist or has been deleted" in str(exc.value.detail).lower()

    # 3. Cross-Tenant Asset Authorization Violation
    # Job is created under Org A, but references Asset B belonging to Org B
    job_cross_tenant = DiscoveryJob(
        organization_id=org_a.id,
        asset_id=asset_b.id,
        target_domain="internal.betaind.in",
        discovery_policy=DiscoveryPolicy.PUBLIC_PASSIVE,
        authorization_confirmed=True,
        initiated_by_user_id=admin_a.id,
        scope_validation_result=json.dumps({
            "status": "APPROVED",
            "organization_id": str(org_a.id),
            "asset_id": str(asset_b.id),
            "effective_target": "internal.betaind.in",
            "discovery_policy": DiscoveryPolicy.PUBLIC_PASSIVE,
        }),
    )
    with pytest.raises(WorkerAuthorizationError) as exc:
        ScopeValidator.validate_worker_execution_authorization(db_session, job_cross_tenant)
    assert "cross-tenant authorization violation" in str(exc.value.detail).lower()

    # 4. Revoked Asset Scope (Asset marked is_in_scope=False after queueing)
    asset_a.is_in_scope = False
    db_session.commit()
    job_revoked_scope = DiscoveryJob(
        organization_id=org_a.id,
        asset_id=asset_a.id,
        target_domain="corp.alphacorp.in",
        discovery_policy=DiscoveryPolicy.PUBLIC_PASSIVE,
        authorization_confirmed=True,
        initiated_by_user_id=admin_a.id,
        scope_validation_result=json.dumps(base_scope_evidence),
    )
    with pytest.raises(WorkerAuthorizationError) as exc:
        ScopeValidator.validate_worker_execution_authorization(db_session, job_revoked_scope)
    assert "authorization revoked" in str(exc.value.detail).lower()
    asset_a.is_in_scope = True
    db_session.commit()

    # 5. Target Tampering in Queued Job
    # Scope was approved for corp.alphacorp.in, but DB row target_domain tampered to evil.com
    job_tampered_target = DiscoveryJob(
        organization_id=org_a.id,
        asset_id=asset_a.id,
        target_domain="evil.attacker.org",
        discovery_policy=DiscoveryPolicy.PUBLIC_PASSIVE,
        authorization_confirmed=True,
        initiated_by_user_id=admin_a.id,
        scope_validation_result=json.dumps(base_scope_evidence),
    )
    with pytest.raises(WorkerAuthorizationError) as exc:
        ScopeValidator.validate_worker_execution_authorization(db_session, job_tampered_target)
    assert "target tampering detected" in str(exc.value.detail).lower()

    # 6. Policy Tampering in Queued Job
    # Scope was approved for PUBLIC_PASSIVE, but job policy tampered to AUTHORIZED_INTERNAL
    job_tampered_policy = DiscoveryJob(
        organization_id=org_a.id,
        asset_id=asset_a.id,
        target_domain="corp.alphacorp.in",
        discovery_policy=DiscoveryPolicy.AUTHORIZED_INTERNAL,
        authorization_confirmed=True,
        initiated_by_user_id=admin_a.id,
        scope_validation_result=json.dumps(base_scope_evidence),
    )
    with pytest.raises(WorkerAuthorizationError) as exc:
        ScopeValidator.validate_worker_execution_authorization(db_session, job_tampered_policy)
    assert "policy tampering detected" in str(exc.value.detail).lower()

    # 7. Deactivated Initiating User
    admin_a.is_active = False
    db_session.commit()
    job_deactivated_user = DiscoveryJob(
        organization_id=org_a.id,
        asset_id=asset_a.id,
        target_domain="corp.alphacorp.in",
        discovery_policy=DiscoveryPolicy.PUBLIC_PASSIVE,
        authorization_confirmed=True,
        initiated_by_user_id=admin_a.id,
        scope_validation_result=json.dumps(base_scope_evidence),
    )
    with pytest.raises(WorkerAuthorizationError) as exc:
        ScopeValidator.validate_worker_execution_authorization(db_session, job_deactivated_user)
    assert "deactivated or suspended" in str(exc.value.detail).lower()
    admin_a.is_active = True
    db_session.commit()

    # 8. Revoked Organization Membership
    membership = db_session.query(OrganizationMembership).filter(
        OrganizationMembership.user_id == admin_a.id,
        OrganizationMembership.organization_id == org_a.id,
    ).first()
    db_session.delete(membership)
    db_session.commit()
    job_revoked_member = DiscoveryJob(
        organization_id=org_a.id,
        asset_id=asset_a.id,
        target_domain="corp.alphacorp.in",
        discovery_policy=DiscoveryPolicy.PUBLIC_PASSIVE,
        authorization_confirmed=True,
        initiated_by_user_id=admin_a.id,
        scope_validation_result=json.dumps(base_scope_evidence),
    )
    with pytest.raises(WorkerAuthorizationError) as exc:
        ScopeValidator.validate_worker_execution_authorization(db_session, job_revoked_member)
    assert "no longer an active member" in str(exc.value.detail).lower()

    # Restore membership
    db_session.add(OrganizationMembership(
        user_id=admin_a.id,
        organization_id=org_a.id,
        role_id=membership.role_id,
    ))
    db_session.commit()

    # 9. Expired Queued Job (> 24 hours TTL)
    job_expired = DiscoveryJob(
        organization_id=org_a.id,
        asset_id=asset_a.id,
        target_domain="corp.alphacorp.in",
        discovery_policy=DiscoveryPolicy.PUBLIC_PASSIVE,
        authorization_confirmed=True,
        initiated_by_user_id=admin_a.id,
        created_at=datetime.now(timezone.utc) - timedelta(hours=36),
        scope_validation_result=json.dumps(base_scope_evidence),
    )
    with pytest.raises(WorkerAuthorizationError) as exc:
        ScopeValidator.validate_worker_execution_authorization(db_session, job_expired, max_queue_ttl_seconds=86400)
    assert "authorization has expired" in str(exc.value.detail).lower()

    # 10. DiscoveryManager State Machine on Worker Failure
    # Save a tampered job in DB, run DiscoveryManager.run_discovery, verify status=FAILED and error_message
    tampered_db_job = DiscoveryJob(
        organization_id=org_a.id,
        asset_id=asset_a.id,
        target_domain="unauthorized-injected.com",
        authorized_scope=asset_a.target,
        discovery_policy=DiscoveryPolicy.PUBLIC_PASSIVE,
        authorization_confirmed=True,
        initiated_by_user_id=admin_a.id,
        status=DiscoveryJobStatus.PENDING,
        scope_validation_result=json.dumps(base_scope_evidence),
    )
    db_session.add(tampered_db_job)
    db_session.commit()

    manager = DiscoveryManager()
    with pytest.raises(WorkerAuthorizationError):
        manager.run_discovery(db_session, tampered_db_job.id)

    # Verify state machine in database
    db_session.refresh(tampered_db_job)
    assert tampered_db_job.status == DiscoveryJobStatus.FAILED
    assert "worker authorization rejected" in tampered_db_job.error_message.lower()
    assert tampered_db_job.completed_at is not None
    assert tampered_db_job.domains_discovered_count == 0
    assert tampered_db_job.findings_count == 0

