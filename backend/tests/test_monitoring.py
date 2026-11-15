"""
PREVENT-X Phase 8 Real-Time Monitoring & Centralized Security Management Tests (MOD-09, MOD-12)

Verification Coverage (15 Scenarios):
1. Nginx log ingestion (standard combined & JSON formats).
2. WAF event ingestion & sanitization (credential redaction, CRLF stripping, 64KB bounded).
3. Real security center overview aggregation (score 0-100, grade, open incidents, WAF telemetry).
4. SSE live update formatting (W3C standard: id, event, data, heartbeat).
5. Reconnection behavior with Last-Event-ID (missed events replay).
6. Duplicate event suppression (identical events within 60s suppressed).
7. Incident creation from correlated evidence (repeated attacks from same IP >= 3).
8. Incident lifecycle and audit timeline history (transitions & analyst notes).
9. Multi-tenant isolation (Org A vs Org B event/incident boundaries).
10. Unauthorized event ingestion rejection (401 & 403 enforcement).
11. Alert generation on critical/high events and 1-click acknowledgement.
12. Malformed and oversized payload rejection (422 validation).
13. Event retention policy management and automated pruning.
14. Celery background worker tasks (process_security_event_job & prune_retained_events_job).
15. Disruptive incident containment human authorization check.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.database.base import utc_now
from backend.app.models.organization import Organization
from backend.app.models.asset import AssetCriticality, AssetType, ManagedAsset
from backend.app.models.monitoring import (
    AlertCategory,
    EventCategory,
    EventRetentionPolicy,
    EventSeverity,
    EventSource,
    IncidentSeverity,
    IncidentStatus,
    SecurityAlert,
    SecurityEvent,
    SecurityIncident,
)
from backend.app.modules.monitoring.correlation_engine import SecurityCorrelationEngine
from backend.app.modules.monitoring.log_parser import NginxLogParser
from backend.app.modules.monitoring.sanitizer import (
    sanitize_headers,
    sanitize_payload,
    sanitize_string,
)
from backend.app.modules.monitoring.schemas import (
    BatchSecurityEventIngestRequest,
    IncidentContainmentRequest,
    IncidentTimelineEntryCreate,
    SecurityEventCreate,
    SecurityIncidentCreate,
    SecurityIncidentUpdate,
)
from backend.app.modules.monitoring.service import MonitoringService
from backend.app.modules.monitoring.sse_manager import SSEManager
from backend.app.modules.monitoring.tasks import (
    process_security_event_job,
    prune_retained_events_job,
)


def _login(client: TestClient, email: str, password: str = "AlphaAdminPass123!") -> str:
    res = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, f"Login failed for {email}: {res.text}"
    return res.json()["tokens"]["access_token"]


# =============================================================================
# SCENARIO 1: NGINX LOG INGESTION (COMBINED & JSON)
# =============================================================================

def test_nginx_combined_and_json_log_ingestion():
    # 1. Combined log format
    combined_log = (
        '198.51.100.12 - - [15/Nov/2026:12:00:00 +0000] '
        '"GET /api/v1/checkout?item=123 HTTP/1.1" 200 452 '
        '"https://example.com" "Mozilla/5.0"'
    )
    parsed_combined = NginxLogParser.parse_line(combined_log)
    assert parsed_combined is not None
    assert parsed_combined["source_ip"] == "198.51.100.12"
    assert parsed_combined["http_method"] == "GET"
    assert parsed_combined["target_uri"] == "/api/v1/checkout?item=123"
    assert parsed_combined["status_code"] == 200
    assert parsed_combined["category"] == EventCategory.SECURITY.value

    # 2. JSON log format
    json_log = json.dumps({
        "remote_addr": "203.0.113.88",
        "request_method": "POST",
        "request_uri": "/api/v1/login",
        "status": 401,
        "request_time": "0.045",
        "http_user_agent": "sqlmap/1.5",
    })
    parsed_json = NginxLogParser.parse_line(json_log)
    assert parsed_json is not None
    assert parsed_json["source_ip"] == "203.0.113.88"
    assert parsed_json["http_method"] == "POST"
    assert parsed_json["target_uri"] == "/api/v1/login"
    assert parsed_json["status_code"] == 401


# =============================================================================
# SCENARIO 2: WAF EVENT INGESTION & SANITIZATION
# =============================================================================

def test_waf_event_ingestion_and_sanitization():
    # Sensitive credentials in headers and query
    headers = {
        "Authorization": "Bearer supersecret-jwt-token-9999",
        "Cookie": "session=sensitive_cookie_value; token=xyz",
        "X-Custom-Header": "harmless_value",
    }
    sanitized_h = sanitize_headers(headers)
    assert sanitized_h["Authorization"] == "[REDACTED]"
    assert sanitized_h["Cookie"] == "[REDACTED]"
    assert sanitized_h["X-Custom-Header"] == "harmless_value"

    # CRLF log injection defense
    malicious_crlf = "GET /login HTTP/1.1\r\nInjected-Header: evil\r\n\r\n"
    sanitized_crlf = sanitize_string(malicious_crlf)
    assert "\r" not in sanitized_crlf
    assert "\n" not in sanitized_crlf

    # Bounded payload to 64KB
    huge_payload = "A" * 100000
    sanitized_huge = sanitize_payload(huge_payload)
    assert len(sanitized_huge.encode("utf-8")) <= 65536 + 64
    assert "[TRUNCATED" in sanitized_huge


# =============================================================================
# SCENARIO 3: SECURITY CENTER OVERVIEW STATS
# =============================================================================

def test_security_center_overview_live_stats(client: TestClient, test_tenants: dict, db_session: Session):
    org_a = test_tenants["org_a"]
    token = _login(client, "admin@alphacorp.in")

    res = client.get(
        "/api/v1/monitoring/overview",
        headers={"Authorization": f"Bearer {token}", "X-Organization-Id": str(org_a.id)},
    )
    assert res.status_code == 200
    data = res.json()

    assert "security_score" in data
    assert 0 <= data["security_score"] <= 100
    assert data["security_grade"] in ["A+", "A", "B", "C", "D", "F"]
    assert "open_incidents_total" in data
    assert "waf_blocked_24h" in data
    assert "waf_allowed_24h" in data
    assert "trust_distribution" in data


# =============================================================================
# SCENARIO 4: SSE LIVE UPDATE FORMATTING
# =============================================================================

def test_sse_live_update_formatting(db_session: Session, test_tenants: dict):
    org_a = test_tenants["org_a"]
    event_id = uuid.uuid4()
    sample_data = {"id": str(event_id), "title": "Test Security Event", "severity": "HIGH"}

    formatted = SSEManager.format_sse_message(
        event_name="security_event",
        data=sample_data,
        event_id=str(event_id),
    )

    lines = formatted.strip().split("\n")
    assert any(line.startswith("id: ") for line in lines)
    assert any(line.startswith("event: security_event") for line in lines)
    assert any(line.startswith("data: ") for line in lines)
    assert formatted.endswith("\n\n")


# =============================================================================
# SCENARIO 5: RECONNECTION WITH LAST-EVENT-ID
# =============================================================================

def test_reconnection_with_last_event_id(db_session: Session, test_tenants: dict):
    org_a = test_tenants["org_a"]
    now = utc_now()

    # Event 1 (older)
    ev1 = SecurityEvent(
        organization_id=org_a.id,
        source=EventSource.SYSTEM.value,
        category=EventCategory.SECURITY.value,
        severity=EventSeverity.INFO.value,
        title="Event 1",
        description="Event 1 desc",
        fingerprint="fp1",
        timestamp=now - timedelta(seconds=20),
    )
    # Event 2 (newer)
    ev2 = SecurityEvent(
        organization_id=org_a.id,
        source=EventSource.SYSTEM.value,
        category=EventCategory.SECURITY.value,
        severity=EventSeverity.HIGH.value,
        title="Event 2",
        description="Event 2 desc",
        fingerprint="fp2",
        timestamp=now - timedelta(seconds=10),
    )
    # Event 3 (newest)
    ev3 = SecurityEvent(
        organization_id=org_a.id,
        source=EventSource.SYSTEM.value,
        category=EventCategory.SECURITY.value,
        severity=EventSeverity.CRITICAL.value,
        title="Event 3",
        description="Event 3 desc",
        fingerprint="fp3",
        timestamp=now - timedelta(seconds=5),
    )
    db_session.add_all([ev1, ev2, ev3])
    db_session.commit()

    # Generator with last_event_id = ev1.id should replay ev2 and ev3
    gen = SSEManager.event_generator(
        db=db_session,
        organization_id=org_a.id,
        last_event_id=str(ev1.id),
        heartbeat_interval=60,
    )

    replayed = []
    # Read messages: msg1 is initial connected confirmation, msg2 and msg3 are replayed events
    msg_connected = next(gen)
    assert "connected" in msg_connected
    msg_ev2 = next(gen)
    msg_ev3 = next(gen)
    replayed.append(msg_ev2)
    replayed.append(msg_ev3)

    combined_text = "".join(replayed)
    assert str(ev2.id) in combined_text
    assert str(ev3.id) in combined_text
    assert str(ev1.id) not in combined_text


# =============================================================================
# SCENARIO 6: DUPLICATE EVENT SUPPRESSION
# =============================================================================

def test_duplicate_event_suppression(db_session: Session, test_tenants: dict):
    org_a = test_tenants["org_a"]

    event_payload = SecurityEventCreate(
        source=EventSource.WAF,
        category=EventCategory.SECURITY,
        severity=EventSeverity.HIGH,
        title="Virtual Patch Blocked XSS Attempt",
        description="Blocked script tag payload in search input",
        source_ip="198.51.100.99",
        target_uri="/search",
        http_method="GET",
        status_code=403,
    )

    # First ingestion -> created
    ev1, is_dup1 = MonitoringService.ingest_single_event(db_session, org_a.id, event_payload)
    assert ev1 is not None
    assert is_dup1 is False

    # Immediate second identical ingestion within 60s -> suppressed
    ev2, is_dup2 = MonitoringService.ingest_single_event(db_session, org_a.id, event_payload)
    assert ev2.id == ev1.id
    assert is_dup2 is True, "Identical event should be suppressed by deduplication fingerprint"


# =============================================================================
# SCENARIO 7: INCIDENT CREATION FROM CORRELATED EVIDENCE
# =============================================================================

def test_incident_creation_from_correlated_evidence(db_session: Session, test_tenants: dict):
    org_a = test_tenants["org_a"]
    hostile_ip = "198.51.100.77"

    # Ingest 3 distinct attacks from same IP within correlation window
    for i in range(3):
        ev = SecurityEvent(
            organization_id=org_a.id,
            source=EventSource.WAF.value,
            category=EventCategory.SECURITY.value,
            severity=EventSeverity.HIGH.value,
            title=f"WAF Block Attack {i+1}",
            description=f"Hostile injection attempt probe {i+1}",
            source_ip=hostile_ip,
            target_uri=f"/api/v1/endpoint_{i+1}",
            http_method="POST",
            status_code=403,
            fingerprint=f"unique_fp_{i}_{uuid.uuid4().hex[:8]}",
            timestamp=utc_now() - timedelta(seconds=(10 - i * 2)),
        )
        db_session.add(ev)
        db_session.flush()

        incident = SecurityCorrelationEngine.evaluate_event(db_session, ev)
        if i == 2:
            assert incident is not None
            assert incident.severity in [IncidentSeverity.HIGH.value, IncidentSeverity.CRITICAL.value]
            assert incident.mitre_attack_id == "T1190"
            assert incident.source == "CORRELATION_ENGINE"


# =============================================================================
# SCENARIO 8: INCIDENT LIFECYCLE AND AUDIT TIMELINE
# =============================================================================

def test_incident_lifecycle_and_audit_timeline(client: TestClient, test_tenants: dict, db_session: Session):
    org_a = test_tenants["org_a"]
    admin_a = test_tenants["admin_a"]
    token = _login(client, "admin@alphacorp.in")

    # 1. Create incident
    create_payload = {
        "title": "Suspected Brute Force Activity",
        "description": "Excessive 401 unauthorized responses detected",
        "severity": "HIGH",
        "mitre_attack_id": "T1110",
        "mitre_technique": "Brute Force",
    }
    res = client.post(
        "/api/v1/monitoring/incidents",
        json=create_payload,
        headers={"Authorization": f"Bearer {token}", "X-Organization-Id": str(org_a.id)},
    )
    assert res.status_code == 201
    inc_data = res.json()
    incident_id = inc_data["id"]
    assert inc_data["status"] == "OPEN"

    # 2. Add Analyst Note
    note_res = client.post(
        f"/api/v1/monitoring/incidents/{incident_id}/notes",
        json={"message": "Analyst investigating origin IPs across geo-lookups.", "entry_type": "ANALYST_NOTE"},
        headers={"Authorization": f"Bearer {token}", "X-Organization-Id": str(org_a.id)},
    )
    assert note_res.status_code == 201
    assert "Analyst investigating" in note_res.json()["message"]

    # 3. Transition status to INVESTIGATING then RESOLVED
    update_res = client.patch(
        f"/api/v1/monitoring/incidents/{incident_id}",
        json={"status": "INVESTIGATING"},
        headers={"Authorization": f"Bearer {token}", "X-Organization-Id": str(org_a.id)},
    )
    assert update_res.status_code == 200
    assert update_res.json()["status"] == "INVESTIGATING"

    resolve_res = client.patch(
        f"/api/v1/monitoring/incidents/{incident_id}",
        json={"status": "RESOLVED", "notes": "Compromised IP blocked at firewall."},
        headers={"Authorization": f"Bearer {token}", "X-Organization-Id": str(org_a.id)},
    )
    assert resolve_res.status_code == 200
    assert resolve_res.json()["status"] == "RESOLVED"

    # 4. Fetch detail and verify timeline
    detail_res = client.get(
        f"/api/v1/monitoring/incidents/{incident_id}",
        headers={"Authorization": f"Bearer {token}", "X-Organization-Id": str(org_a.id)},
    )
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert len(detail["timeline_entries"]) >= 3  # CREATED, NOTE, STATUS_CHANGE x2


# =============================================================================
# SCENARIO 9: MULTI-TENANT ISOLATION
# =============================================================================

def test_multi_tenant_isolation(client: TestClient, test_tenants: dict, db_session: Session):
    org_a = test_tenants["org_a"]
    org_b = test_tenants["org_b"]

    token_a = _login(client, "admin@alphacorp.in", "AlphaAdminPass123!")
    token_b = _login(client, "admin@betaind.in", "BetaAdminPass123!")

    # Ingest event for Org A
    ingest_req = {
        "events": [
            {
                "source": "SYSTEM",
                "category": "SECURITY",
                "severity": "HIGH",
                "title": "Org A Confidential Security Alert",
                "description": "Sensitive Org A Telemetry",
            }
        ]
    }
    res_a = client.post(
        "/api/v1/monitoring/events/ingest",
        json=ingest_req,
        headers={"Authorization": f"Bearer {token_a}", "X-Organization-Id": str(org_a.id)},
    )
    assert res_a.status_code == 200
    created_id = res_a.json()["event_ids"][0]

    # Query events as Org B -> Org A event MUST NOT appear
    res_b = client.get(
        "/api/v1/monitoring/events",
        headers={"Authorization": f"Bearer {token_b}", "X-Organization-Id": str(org_b.id)},
    )
    assert res_b.status_code == 200
    items_b = res_b.json()["items"]
    assert not any(item["id"] == created_id for item in items_b)


# =============================================================================
# SCENARIO 10: UNAUTHORIZED EVENT INGESTION REJECTION
# =============================================================================

def test_unauthorized_event_ingestion_rejection(client: TestClient, test_tenants: dict):
    org_a = test_tenants["org_a"]
    payload = {
        "events": [
            {
                "title": "Unauthorized Probe",
                "description": "Should fail",
            }
        ]
    }

    # 1. Anonymous request -> 401 Unauthorized
    anon_res = client.post("/api/v1/monitoring/events/ingest", json=payload)
    assert anon_res.status_code == 401

    # 2. Viewer role attempting ingestion -> 403 Forbidden
    viewer_token = _login(client, "viewer@betaind.in", "BetaViewerPass123!")
    org_b = test_tenants["org_b"]
    forbidden_res = client.post(
        "/api/v1/monitoring/events/ingest",
        json=payload,
        headers={"Authorization": f"Bearer {viewer_token}", "X-Organization-Id": str(org_b.id)},
    )
    assert forbidden_res.status_code == 403


# =============================================================================
# SCENARIO 11: ALERT GENERATION & ACKNOWLEDGEMENT
# =============================================================================

def test_alert_generation_and_acknowledgement(client: TestClient, test_tenants: dict, db_session: Session):
    org_a = test_tenants["org_a"]
    token = _login(client, "admin@alphacorp.in")

    # Ingest a CRITICAL event -> triggers in-app alert
    ingest_req = {
        "events": [
            {
                "source": "WAF",
                "category": "SECURITY",
                "severity": "CRITICAL",
                "title": "Critical RCE Exploit Pattern Detected",
                "description": "System command injection in query string",
            }
        ]
    }
    client.post(
        "/api/v1/monitoring/events/ingest",
        json=ingest_req,
        headers={"Authorization": f"Bearer {token}", "X-Organization-Id": str(org_a.id)},
    )

    # Fetch alerts
    alerts_res = client.get(
        "/api/v1/monitoring/alerts?is_acknowledged=false",
        headers={"Authorization": f"Bearer {token}", "X-Organization-Id": str(org_a.id)},
    )
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    assert len(alerts) > 0
    target_alert = alerts[0]
    assert not target_alert["is_acknowledged"]

    # Acknowledge alert
    ack_res = client.post(
        f"/api/v1/monitoring/alerts/{target_alert['id']}/acknowledge",
        headers={"Authorization": f"Bearer {token}", "X-Organization-Id": str(org_a.id)},
    )
    assert ack_res.status_code == 200
    assert ack_res.json()["is_acknowledged"] is True


# =============================================================================
# SCENARIO 12: MALFORMED AND OVERSIZED PAYLOAD REJECTION
# =============================================================================

def test_malformed_and_oversized_payload_rejection(client: TestClient, test_tenants: dict):
    org_a = test_tenants["org_a"]
    token = _login(client, "admin@alphacorp.in")

    # 1. Malformed missing required title
    bad_res = client.post(
        "/api/v1/monitoring/events/ingest",
        json={"events": [{"source": "SYSTEM"}]},  # Missing title & description
        headers={"Authorization": f"Bearer {token}", "X-Organization-Id": str(org_a.id)},
    )
    assert bad_res.status_code == 422

    # 2. Oversized raw_nginx_logs (> 1MB)
    oversized_res = client.post(
        "/api/v1/monitoring/events/ingest",
        json={"raw_nginx_logs": "X" * (1048576 + 100)},
        headers={"Authorization": f"Bearer {token}", "X-Organization-Id": str(org_a.id)},
    )
    assert oversized_res.status_code == 422


# =============================================================================
# SCENARIO 13: EVENT RETENTION POLICY & PRUNING
# =============================================================================

def test_event_retention_policy_and_pruning(client: TestClient, test_tenants: dict, db_session: Session):
    org_a = test_tenants["org_a"]
    token = _login(client, "admin@alphacorp.in")

    # Update retention policy: 2 days, max 1000 events
    update_res = client.put(
        "/api/v1/monitoring/retention",
        json={"retention_days": 2, "max_stored_events": 1000, "auto_prune_enabled": True},
        headers={"Authorization": f"Bearer {token}", "X-Organization-Id": str(org_a.id)},
    )
    assert update_res.status_code == 200
    assert update_res.json()["retention_days"] == 2

    # Insert an old event (3 days old) and a fresh event
    old_ev = SecurityEvent(
        organization_id=org_a.id,
        source="SYSTEM",
        category="TRAFFIC",
        severity="INFO",
        title="Old Event",
        description="Expired",
        fingerprint="old_fp_" + uuid.uuid4().hex[:8],
        timestamp=utc_now() - timedelta(days=3),
    )
    fresh_ev = SecurityEvent(
        organization_id=org_a.id,
        source="SYSTEM",
        category="TRAFFIC",
        severity="INFO",
        title="Fresh Event",
        description="Current",
        fingerprint="fresh_fp_" + uuid.uuid4().hex[:8],
        timestamp=utc_now(),
    )
    db_session.add_all([old_ev, fresh_ev])
    db_session.commit()

    # Trigger prune
    prune_res = client.post(
        "/api/v1/monitoring/retention/prune",
        headers={"Authorization": f"Bearer {token}", "X-Organization-Id": str(org_a.id)},
    )
    assert prune_res.status_code == 200
    assert prune_res.json()["deleted_events_count"] >= 1

    # Verify old event deleted
    db_session.expire_all()
    check_old = db_session.query(SecurityEvent).filter(SecurityEvent.id == old_ev.id).first()
    check_fresh = db_session.query(SecurityEvent).filter(SecurityEvent.id == fresh_ev.id).first()
    assert check_old is None
    assert check_fresh is not None


# =============================================================================
# SCENARIO 14: CELERY BACKGROUND WORKER TASKS
# =============================================================================

def test_celery_monitoring_tasks():
    from backend.app.database.session import SessionLocal

    local_db = SessionLocal()
    test_org = Organization(
        name="Celery Monitoring Test Org",
        slug=f"celery-mon-{uuid.uuid4().hex[:8]}",
        contact_email="celery-mon@preventx.test",
        is_active=True,
    )
    local_db.add(test_org)
    local_db.commit()

    try:
        # 1. Synchronously execute process_security_event_job via apply()
        ev = SecurityEvent(
            organization_id=test_org.id,
            source="SYSTEM",
            category="SECURITY",
            severity="HIGH",
            title="Celery Tested Event",
            description="Background task verification",
            fingerprint="celery_fp_" + uuid.uuid4().hex[:8],
            timestamp=utc_now(),
        )
        local_db.add(ev)
        local_db.commit()

        task_res = process_security_event_job.apply(args=[str(ev.id)])
        assert task_res.status == "SUCCESS"
        res_data = task_res.result
        assert res_data["status"] == "processed"
        assert res_data["event_id"] == str(ev.id)

        # 2. Synchronously execute prune_retained_events_job via apply()
        prune_task = prune_retained_events_job.apply()
        assert prune_task.status == "SUCCESS"
        assert prune_task.result["status"] == "completed"
    finally:
        local_db.query(SecurityEvent).filter(SecurityEvent.organization_id == test_org.id).delete()
        local_db.query(Organization).filter(Organization.id == test_org.id).delete()
        local_db.commit()
        local_db.close()


# =============================================================================
# SCENARIO 15: DISRUPTIVE INCIDENT CONTAINMENT HUMAN AUTHORIZATION CHECK
# =============================================================================

def test_disruptive_containment_authorization_gate(client: TestClient, test_tenants: dict, db_session: Session):
    org_a = test_tenants["org_a"]

    # Create incident
    inc = SecurityIncident(
        incident_number="INC-202611-TESTGATE",
        organization_id=org_a.id,
        title="Active Brute Force Attack",
        description="Automated login credential spraying",
        severity="HIGH",
        status="OPEN",
        source="SYSTEM",
        containment_requires_approval=True,
    )
    db_session.add(inc)
    db_session.commit()

    # 1. Analyst attempts containment without approval flag -> requires approval
    analyst_token = _login(client, "analyst@alphacorp.in", "AlphaAnalystPass123!")
    req_no_approval = {
        "containment_action": "BLOCK_SOURCE_IP",
        "notes": "Proposed blocking IP at edge",
        "is_approved": False,
    }
    res_analyst = client.post(
        f"/api/v1/monitoring/incidents/{inc.id}/contain",
        json=req_no_approval,
        headers={"Authorization": f"Bearer {analyst_token}", "X-Organization-Id": str(org_a.id)},
    )
    assert res_analyst.status_code == 200
    assert res_analyst.json()["containment_requires_approval"] is True
    assert res_analyst.json()["status"] == "OPEN"

    # 2. Org Admin executes with explicit human approval flag -> executed and status marked CONTAINED
    admin_token = _login(client, "admin@alphacorp.in")
    req_approved = {
        "containment_action": "BLOCK_SOURCE_IP",
        "notes": "Admin approved edge IP block",
        "is_approved": True,
    }
    res_admin = client.post(
        f"/api/v1/monitoring/incidents/{inc.id}/contain",
        json=req_approved,
        headers={"Authorization": f"Bearer {admin_token}", "X-Organization-Id": str(org_a.id)},
    )
    assert res_admin.status_code == 200
    assert res_admin.json()["containment_requires_approval"] is False
    assert res_admin.json()["status"] == "CONTAINED"
    assert res_admin.json()["containment_action_taken"] == "BLOCK_SOURCE_IP"
