"""
PREVENT-X System Health and Telemetry Tests
"""

def test_health_liveness_endpoint(client):
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "HEALTHY"
    assert "version" in data
    assert "timestamp" in data


def test_ready_readiness_endpoint(client):
    resp = client.get("/api/v1/ready")
    assert resp.status_code == 200
    data = resp.json()
    assert data["database"]["status"] == "UP"
    assert "latency_ms" in data["database"]
    assert "redis" in data


def test_system_info_and_module_catalog(client):
    resp = client.get("/api/v1/system/info")
    assert resp.status_code == 200
    data = resp.json()
    assert data["app_name"] == "PREVENT-X"
    assert data["phase"] == "PHASE 1: ENTERPRISE-GRADE FOUNDATION & ARCHITECTURE"
    assert "modules" in data
    assert len(data["modules"]) == 12

    # Check MOD-08 (Intelligent Virtual Patching Engine) is marked as planned/stub, NOT fake operational
    mod_08 = next((m for m in data["modules"] if m["module_id"] == "MOD-08"), None)
    assert mod_08 is not None
    assert mod_08["name"] == "Intelligent Virtual Patching Engine"
    assert mod_08["status"] in ["PLANNED_PHASE", "ARCHITECTURAL_STUB"]
    assert mod_08["phase"] == 6

    # Check MOD-12 (Centralized SMB Security Platform) is OPERATIONAL in Phase 1
    mod_12 = next((m for m in data["modules"] if m["module_id"] == "MOD-12"), None)
    assert mod_12 is not None
    assert mod_12["status"] == "OPERATIONAL"
    assert mod_12["phase"] == 1

