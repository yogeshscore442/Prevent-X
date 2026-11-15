# PREVENT-X Phase 8: Real-Time Monitoring & Centralized Security Center (MOD-09, MOD-12)

## Executive Summary

Phase 8 introduces the **Real-Time Traffic Monitoring Engine (`MOD-09`)** and the **Centralized SMB Security Management Platform (`MOD-12`)** into PREVENT-X. Designed specifically for Indian Small and Medium Businesses (SMBs) running digital storefronts, fintech gateways, and web APIs, this module brings together telemetry from all preceding phases:
- Real-time ingestion and sanitization of Nginx reverse proxy access and error logs.
- WAF rule execution events and virtual patch mitigations from Phase 6 (`MOD-06`, `MOD-08`).
- Zero Trust risk and trust-assessment changes from Phase 5 (`MOD-04`).
- Attack surface findings and active scan events from Phase 2 (`MOD-01`).
- Vulnerability mappings from Phase 3 (`MOD-02`) and Attack Path discoveries from Phase 4 (`MOD-03`).
- Security validation jobs, proxy canary routing, and rollback events from Phase 7 (`MOD-10`, `MOD-11`).

All telemetry streams into an automated correlation engine mapped to the **MITRE ATT&CK** matrix, driving real-time Server-Sent Events (SSE) to an interactive, centralized dashboard (`/security-center`).

---

## Architecture Overview

```
                                      +---------------------------------------------+
                                      |   Nginx Reverse Proxy / WAF Enforcement     |
                                      +---------------------------------------------+
                                                             |
                                                             v Raw Logs & WAF Telemetry
+-----------------------------------+         +---------------------------------------------+
| External Log Streams / Adapters   | ------> | POST /api/v1/monitoring/events/ingest       |
+-----------------------------------+         +---------------------------------------------+
                                                             |
                                                             v
                                              +-------------------------------+
                                              | Sanitizer & Ingestion Engine  |
                                              | - Strips CRLF (Log Injection) |
                                              | - Redacts Credentials/Tokens  |
                                              | - Bounds Payloads (<= 64KB)   |
                                              | - Computes SHA256 Fingerprint |
                                              | - 60s Duplicate Suppression   |
                                              +-------------------------------+
                                                             |
                                      +----------------------+----------------------+
                                      |                                             |
                                      v                                             v
                      +-------------------------------+             +-------------------------------+
                      | PostgreSQL 16 Data Store      |             | Redis 8 Pub/Sub Broker        |
                      | - security_events             |             | Channel:                      |
                      | - security_incidents          |             | preventx:events:{org_id}      |
                      | - incident_timeline_entries   |             +-------------------------------+
                      | - security_alerts             |                             |
                      | - event_retention_policies    |                             v
                      +-------------------------------+             +-------------------------------+
                                      |                             | Server-Sent Events (SSE)      |
                                      v                             | GET /events/stream            |
                      +-------------------------------+             | - Token Auth in Query/Header  |
                      | Security Correlation Engine   |             | - Missed Replay (Last-Event)  |
                      | - Repeated IP Attacks (T1190) |             | - 15s Heartbeat Keepalives    |
                      | - Vulnerable Probing (T1190)  |             +-------------------------------+
                      | - Zero Trust Degraded (T1078) |                             |
                      | - Rollback Failures (T1059)   |                             v
                      +-------------------------------+             +-------------------------------+
                                      |                             | Frontend Security Center      |
                                      v                             | (/security-center)            |
                      +-------------------------------+             | - Executive Posture Score     |
                      | Containment Workflow          |             | - Live Event Telemetry Stream |
                      | - Block Source IP             |             | - Incident Mgmt & Timeline    |
                      | - Deploy Virtual Patch        |             | - Alerts & Data Retention     |
                      | - Human Auth Approval Gate    |             +-------------------------------+
                      +-------------------------------+
```

---

## Key Capabilities Implemented

### 1. Ingestion Pipeline & Defense-in-Depth Sanitization
- **Multi-Format Parser (`NginxLogParser`)**: Natively parses standard combined Nginx access log format, Nginx JSON structured log format, and Nginx error log lines, extracting status codes, request methods, client IP addresses, target URIs, and user agents.
- **Credential Redaction (`Sanitizer`)**: Cryptographically redacts sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `X-CSRF-Token`) and sensitive query parameters (`password`, `token`, `secret`, `api_key`) to prevent sensitive data leakage in logs.
- **Log Injection Defense**: Strips CRLF characters (`\r`, `\n`) from all fields to prevent HTTP response splitting and log forgery attacks.
- **Bounded Payloads**: Limits raw payloads to a strict 64KB boundary with standard truncation markers to prevent memory exhaustion and DoS attacks.
- **Sliding Deduplication Fingerprint**: Computes `SHA256(org_id:source:category:source_ip:target_uri:title)`. If an identical event arrives within a 60-second window, database re-insertion is suppressed while preserving telemetry counts.

### 2. Real-Time Streaming & Reconnection (SSE)
- **Redis Pub/Sub Integration**: Live events are published to tenant-isolated Redis channels (`preventx:events:{organization_id}`).
- **W3C Server-Sent Events**: Endpoint `/api/v1/monitoring/events/stream` streams events using standard `id:`, `event:`, and `data:` formatting.
- **Query Parameter Token Auth**: Accepts JWT tokens via `?token=...` in query parameters to support native browser `EventSource` connections where custom headers are unsupported.
- **Missed Events Replay**: When a browser reconnects with a `Last-Event-ID` header or parameter, the server queries PostgreSQL for any missed events since that event's timestamp and replays them before switching to the live Redis stream.
- **Heartbeat Keepalives**: Emits periodic keepalive comments (`: keepalive {timestamp}`) every 15 seconds to prevent intermediate proxy or firewall connection drops.

### 3. Evidence-Backed Incident Correlation Engine
- **Correlation Rules**:
  - `CORR-01`: Repeated attacks from the same source IP address ($\ge 3$ attacks within 10 minutes) automatically correlate into an incident mapped to **MITRE ATT&CK T1190** (Exploit Public-Facing Application).
  - `CORR-02`: Malicious probing targeting an endpoint with a known confirmed vulnerability on that asset correlates into an incident mapped to **MITRE ATT&CK T1190**.
  - `CORR-03`: Posture degradation on sensitive assets (e.g. state change to `UNTRUSTED`) correlates into an incident mapped to **MITRE ATT&CK T1078** (Valid Accounts / Abuse).
  - `CORR-04`: Security validation or automated rollback failures trigger an operational incident mapped to **MITRE ATT&CK T1059**.
- **Incident Lifecycle**:
  - Sequential, human-readable incident numbers (`INC-{YYYY}-{seq:04d}`).
  - Status progression: `OPEN` $\rightarrow$ `ACKNOWLEDGED` $\rightarrow$ `INVESTIGATING` $\rightarrow$ `CONTAINED` $\rightarrow$ `RESOLVED` $\rightarrow$ `CLOSED`.
  - Immutable timeline entries capturing state transitions, analyst notes, and containment executions.
- **Human Authorization Gate**:
  - Security Analysts can propose containment actions, which sets `containment_requires_approval = True`.
  - Only `ORG_ADMIN` or `SUPER_ADMIN` can authorize and execute disruptive containment actions (`BLOCK_SOURCE_IP`, `DEPLOY_VIRTUAL_PATCH`, `ISOLATE_ASSET`).

### 4. Centralized SMB Security Management Dashboard (`/security-center`)
- **Executive Security Posture Score**:
  - Dynamic score from 0 to 100 with rating letter grade (`A+`, `A`, `B`, `C`, `D`, `F`).
  - Evidence-backed deductions: 15 points per open Critical incident, 8 points per open High incident, 3 points per Medium incident, 5 points per Untrusted asset, and 5 points per validation failure.
- **Live Event Stream Table**: Real-time table streaming events with connection status badge, pause/resume controls, search, severity/category filters, and modal payload inspector.
- **Incident Management Drawer**: Full lifecycle controls, status dropdown, timeline log, analyst note entry form, and containment approval interface.
- **In-App Operational Alerts**: Dedicated operational alerts list with 1-click acknowledge button.
- **Configurable Retention Policy**: Allows administrators to configure retention windows (1-365 days) and maximum stored events limits (1,000 to 1,000,000), backed by automated Celery pruning (`prune_retained_events_job`).

---

## Verification & Test Results

### Backend Test Matrix (`backend/tests/test_monitoring.py`)
| # | Test Case | Target Capability | Result |
|---|---|---|---|
| 1 | `test_nginx_combined_and_json_log_ingestion` | Parsing standard combined & JSON Nginx logs | **PASSED** |
| 2 | `test_waf_event_ingestion_and_sanitization` | Redaction of tokens, CRLF stripping, 64KB bound | **PASSED** |
| 3 | `test_security_center_overview_live_stats` | Executive score 0-100, open incidents, WAF telemetry | **PASSED** |
| 4 | `test_sse_live_update_formatting` | W3C SSE standard lines (`id:`, `event:`, `data:`) | **PASSED** |
| 5 | `test_reconnection_with_last_event_id` | Replaying missed events using `Last-Event-ID` | **PASSED** |
| 6 | `test_duplicate_event_suppression` | 60-second sliding deduplication fingerprint | **PASSED** |
| 7 | `test_incident_creation_from_correlated_evidence` | Auto-incident creation on repeated source IP attacks | **PASSED** |
| 8 | `test_incident_lifecycle_and_audit_timeline` | Transitions: Open $\rightarrow$ Investigating $\rightarrow$ Resolved | **PASSED** |
| 9 | `test_multi_tenant_isolation` | Org A events/incidents inaccessible to Org B | **PASSED** |
| 10 | `test_unauthorized_event_ingestion_rejection` | 401 Unauthorized & 403 Forbidden enforcement | **PASSED** |
| 11 | `test_alert_generation_and_acknowledgement` | Auto-alert on Critical event & 1-click acknowledge | **PASSED** |
| 12 | `test_malformed_and_oversized_payload_rejection` | 422 Unprocessable Entity on invalid/oversized logs | **PASSED** |
| 13 | `test_event_retention_policy_and_pruning` | Retention window enforcement & event pruning | **PASSED** |
| 14 | `test_celery_monitoring_tasks` | Asynchronous event processing & retention pruning jobs | **PASSED** |
| 15 | `test_disruptive_containment_authorization_gate` | Non-admin requires approval; Admin can execute | **PASSED** |

### Frontend Test Matrix (`frontend/tests/security_center.test.tsx`)
| # | Test Case | Target Capability | Result |
|---|---|---|---|
| 1 | Posture score and KPI rendering | Score, grade, events count, WAF blocked metrics | **PASSED** |
| 2 | Live Security Events tab | Navigation and rendering of incoming event rows | **PASSED** |
| 3 | Correlated Incidents tab | Selection, detail drawer, and containment workflow | **PASSED** |
| 4 | In-App Alerts & Retention tab | Alert list rendering and 1-click acknowledgement | **PASSED** |

---

## Operational Endpoints Reference

| Method | Endpoint | RBAC Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/monitoring/overview` | `monitoring:read` | Centralized SMB security health score and telemetry |
| `POST` | `/api/v1/monitoring/events/ingest` | `monitoring:ingest` | Ingest structured events or raw Nginx access/error logs |
| `GET` | `/api/v1/monitoring/events` | `monitoring:read` | Paginated query of security events with filters |
| `GET` | `/api/v1/monitoring/events/stream` | `monitoring:read` | Real-time SSE stream with token auth and reconnection replay |
| `GET` | `/api/v1/monitoring/incidents` | `incident:read` | List correlated and manual security incidents |
| `POST` | `/api/v1/monitoring/incidents` | `incident:manage` | Manually record an operational security incident |
| `GET` | `/api/v1/monitoring/incidents/{id}` | `incident:read` | Retrieve full incident detail with audit timeline |
| `PATCH` | `/api/v1/monitoring/incidents/{id}` | `incident:manage` | Update incident status, severity, or assignee |
| `POST` | `/api/v1/monitoring/incidents/{id}/notes` | `incident:manage` | Add analyst investigation notes to timeline |
| `POST` | `/api/v1/monitoring/incidents/{id}/contain` | `incident:manage` | Propose or execute disruptive containment action |
| `GET` | `/api/v1/monitoring/alerts` | `monitoring:read` | List in-app operational security alerts |
| `POST` | `/api/v1/monitoring/alerts/{id}/acknowledge` | `alert:manage` | Mark an alert as acknowledged by current user |
| `GET` | `/api/v1/monitoring/retention` | `retention:manage` | View tenant event retention settings |
| `PUT` | `/api/v1/monitoring/retention` | `retention:manage` | Update tenant event retention window and storage limit |
| `POST` | `/api/v1/monitoring/retention/prune` | `retention:manage` | Immediately prune expired security telemetry |

