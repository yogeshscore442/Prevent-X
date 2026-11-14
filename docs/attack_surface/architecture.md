# PREVENT-X — Attack Surface Intelligence Engine (MOD-01) Architecture

## 1. Engine Purpose and Problem Alignment

PREVENT-X addresses NASSCOM Applied Research Bridge 2.0 Problem Statement 5 (PS-05): *"AI-Era Virtual Patching for Security Protection of Indian SMB Digital Businesses."*

The **Attack Surface Intelligence Engine (MOD-01)** is the foundational reconnaissance module of PREVENT-X. Before compensating security controls or virtual patches can be synthesized and deployed, the platform must accurately map the customer's exposed digital boundary.

Indian SMBs operate under unique structural constraints:
- Fragmented hosting environments (multi-cloud, shared hosts, on-premise routers).
- Unmonitored subdomain proliferation created by third-party SaaS tools.
- Limited IT security staffing to maintain asset inventories.
- High risk of domain spoofing, dangling DNS takeovers, and expired TLS certificates.

MOD-01 provides non-intrusive, 100% passive external reconnaissance that continuously discovers, catalogs, and monitors external SMB digital exposure points without triggering disruptive IDS/IPS alerts or service outages.

---

## 2. Architectural Structure

The module is organized under `backend/app/modules/attack_surface/` with strict separation of concerns:

```
backend/app/modules/attack_surface/
├── __init__.py                 # Module exports and lifecycle registration
├── interfaces.py               # Abstract protocols for collectors, validators, and scoring
├── schemas.py                  # Pydantic v2 schemas for API requests, telemetry, and metrics
├── scope_validator.py          # Mandatory multi-tenant boundary and SSRF protection service
├── discovery_manager.py        # State machine orchestrating collection stages and resilience
├── evidence_manager.py         # Transforms telemetry into categorized, actionable findings
├── risk_engine.py              # Deterministic, explainable 0–100 exposure risk engine
├── service.py                  # Business logic coordinator, audit logger, and query service
├── adapters/
│   ├── __init__.py
│   ├── certificate_transparency.py  # crt.sh JSON integration with wildcard handling
│   ├── dns_intelligence.py         # dnspython resolver (A, AAAA, CNAME, MX, NS, TXT, SPF, DMARC)
│   └── rdap.py                     # rdap.org client with mandatory PII redaction
└── tasks/
    ├── __init__.py
    └── discovery_tasks.py      # Celery task definitions executed on Redis broker
```

---

## 3. Database Entities & Migration 002

All entities are mapped to PostgreSQL 16 using typed SQLAlchemy 2.0 declarations with GUID primary keys, cascading tenant foreign keys, and indexes:

1. **`discovery_jobs`**: Tracks job status (`PENDING`, `QUEUED`, `RUNNING`, `COMPLETED`, `PARTIALLY_COMPLETED`, `FAILED`, `CANCELLED`), progress percentage, active stage, initiating user, authorization timestamp, and risk score.
2. **`discovered_domains`**: Unique table of external hostnames and subdomains scoped to `organization_id` with `(organization_id, domain_name)` unique constraint, parent domain links, and observation timestamps.
3. **`dns_records`**: Detailed DNS telemetry records (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SPF`, `DMARC`) with TTL and resolution status.
4. **`certificate_evidence`**: Public Certificate Transparency evidence including Common Name, Subject Alternative Names (SAN), issuer, validity ranges, wildcard flags, and expiry flags.
5. **`rdap_records`**: Privacy-safe domain registration profile containing registrar name, handle, registration/expiration timelines, and nameservers.
6. **`exposure_findings`**: Individual categorized exposure findings (`PUBLIC_DOMAIN`, `DISCOVERED_SUBDOMAIN`, `PUBLIC_IP`, `DNS_CONFIGURATION`, `CERTIFICATE_EXPOSURE`, `UNKNOWN_ASSET_RELATIONSHIP`) with severity, confidence, and structured JSON evidence.

---

## 4. Asynchronous Pipeline Integration (Celery + Redis)

```
[FastAPI Client]
      │
      ▼ (POST /api/v1/attack-surface/discovery)
[ScopeValidator] ──(Validates Scope, SSRF, Tenant Ownership)
      │
      ▼ (Persists job in PostgreSQL with status QUEUED)
[AttackSurfaceService]
      │
      ▼ (Dispatches preventx.tasks.execute_discovery_job)
[Redis Broker (DB 1)]
      │
      ▼ (Pulls job task)
[Celery Solo Worker] ──(Calls DiscoveryManager.run_discovery)
      │
      ├─► [CertificateTransparencyAdapter (crt.sh)]
      ├─► [DNSIntelligenceAdapter (dnspython)]
      ├─► [RDAPAdapter (rdap.org)]
      ├─► [DeterministicRiskEngine]
      └─► [EvidenceManager]
      │
      ▼ (Persists Domains, DNS, Certs, RDAP, Findings & Updates Job to COMPLETED)
[PostgreSQL Database (port 54320)]
```

---

## 5. Security and Operational Boundaries

- **Strictly Passive**: Absolutely NO active port scanning (Nmap/Masscan), NO vulnerability fuzzing, and NO exploitation attempts.
- **SSRF Defenses**: Rejects private RFC 1918 ranges, loopback, link-local, carrier-grade NAT, cloud metadata (169.254.169.254), and internal TLDs (`.local`, `.internal`).
- **Tenant Scoping**: All operations require an authenticated user with appropriate permissions (`discovery:create`, `discovery:read`, `discovery:cancel`) scoped to their active organization.
