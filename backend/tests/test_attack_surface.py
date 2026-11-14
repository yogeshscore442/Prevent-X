"""
PREVENT-X Attack Surface Intelligence Engine Tests (Phase 2 Prompt 1)
Validates scope boundaries, SSRF prevention, adapters, deterministic risk scoring,
evidence generation, asynchronous task execution, and API endpoints with tenant isolation.
"""

import json
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient

from backend.app.models.attack_surface import (
    DiscoveryJob,
    DiscoveryJobStatus,
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
    val_asset, effective_target, effective_policy = ScopeValidator.validate_and_authorize_job(
        db=db_session,
        organization_id=org_a.id,
        asset_id=asset.id,
        target_domain="sub.portal.smbclient.in",
        authorization_confirmed=True,
    )
    assert val_asset.id == asset.id
    assert effective_target == "sub.portal.smbclient.in"
    assert effective_policy == "PUBLIC_PASSIVE"


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
    val_asset, effective_target, pol = ScopeValidator.validate_and_authorize_job(
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
