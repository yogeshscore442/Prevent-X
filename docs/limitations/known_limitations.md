# PREVENT-X Phase 1 Known Limitations & Boundaries

In accordance with the Phase 1 specification, the following boundaries and intentional limitations apply:

---

## 1. Scope Limitations of Phase 1
1. **No Active Network Vulnerability Scanning**:
   - Phase 1 provides the authorized **Managed Asset Inventory** foundation (`managed_assets` table and CRUD APIs).
   - Actual network port scanning, service probing, and passive banner grabbing are deferred to **Phase 2 (Attack Surface Intelligence Engine)**.
2. **No Live Virtual Patch Rule Synthesis**:
   - Schema definitions (`virtual_patch_rules`, `validation_results`, `deployment_records`) and module boundaries (`MOD-08`) are declared.
   - Real automatic generation of ModSecurity/Envoy/Nginx WAF rules from CVEs is deferred to **Phase 6 (Intelligent Virtual Patching Engine)**.
3. **No Automated Live Traffic Blocking**:
   - Reverse proxy rate limiting and basic IP throttling are active in Nginx and FastAPI middleware.
   - Deep packet inspection and machine-learning anomaly blocking are deferred to **Phase 7 (Real-Time Traffic Monitoring Engine)**.
4. **Environment Execution**:
   - On the local developer machine where Docker daemon is not active, the application runs using Python 3.10 virtual environment and SQLite with full migration tracking, while Docker Compose and PostgreSQL configurations are verified and documented for production containers.

---

## 2. Planned Evolution
- **Phase 2**: Attack Surface Intelligence Engine (authorized asset discovery and technology stack fingerprinting).
- **Phase 3**: Advanced Vulnerability Mapping Engine (CVE/NVD ingestion and asset correlation).
- **Phase 4**: Attack Path Analysis & Zero Trust Engines.
- **Phase 5**: AI Threat Intelligence & Hardening Engines.
- **Phase 6**: Intelligent Virtual Patching & Zero-Day Resilience Engines.
- **Phase 7**: Real-Time Traffic Monitoring & Security Validation Engines.
- **Phase 8**: Automated Response & Reliable Rollback Engine.
- **Phase 9**: Production Hardening & Full Scale Enterprise Readiness.
