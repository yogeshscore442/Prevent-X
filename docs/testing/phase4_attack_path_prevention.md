# PREVENT-X — Phase 4 Verification & Evidence Report: AI Attack Path & Prevention Engine (MOD-03)

**Date**: 2026-11-14  
**Module**: MOD-03 (AI Attack Path and Prevention Engine)  
**Problem Statement**: NASSCOM Applied Research Bridge 2.0, Problem Statement 5: *"AI-Era Virtual Patching for Security Protection of Indian SMB Digital Businesses"*  
**Verification Environment**: 
- **Database**: Real PostgreSQL 16 server (Port 54320)
- **Broker**: Real Redis 8.10.3 server (Port 6379)
- **Asynchronous Worker**: Real Celery worker (solo pool)
- **Frontend**: Vite 5.4 + React 18 + TypeScript + Tailwind CSS

---

## 1. Executive Summary

Phase 4 of PREVENT-X introduces an evidence-backed **AI Attack Path and Prevention Engine (MOD-03)** designed specifically for Indian SMB digital businesses. Rather than assuming hypothetical or synthetic compromise chains, the engine analyzes empirical telemetry collected from Phase 2 (Discovered Services, Ports, TLS, Subnets) and Phase 3 (CVE Mapping, CVSS, CISA KEV Exploitability) along with explicitly verified **Asset Trust Relationships** to construct Directed Acyclic Graphs (DAGs) modeling adversary lateral traversal.

The system synthesizes prioritized, SMB-friendly **Compensating Controls (Virtual Patching, Micro-Segmentation, MFA, Service Hardening)** that break attack chains at strategic choke points before adversaries reach high-value crown jewel databases and internal servers.

---

## 2. Core Capabilities Implemented

### 2.1 Multi-Hop DAG Attack Path Construction
- **Entry Point Classification**: Identifies public-facing DMZ assets (`DOMAIN`, `PUBLIC_IP`, `WEB_APPLICATION`, open ports 80/443/22/3389).
- **Crown Jewel Identification**: Targets flagged with `CRITICAL` or `HIGH` asset criticality, database technologies (PostgreSQL, MySQL, Oracle, MongoDB, Redis), and identity repositories.
- **Evidence-Backed Adjacency**: Traverses hops based **strictly** on verified records:
  1. Explicit `AssetTrustRelationship` records (`DATABASE_LINK`, `SSH_ADMIN_ACCESS`, `ACTIVE_DIRECTORY_TRUST`, `API_DEPENDENCY`).
  2. Verified common private subnet matching (`/24` CIDR intersection between internal hosts).
- **Zero Hallucination Policy**: When two assets have no verified trust relationship or network reachability, the engine strictly refuses to synthesize a lateral movement edge.

### 2.2 MITRE ATT&CK Matrix Mapping
Every hop and vulnerability finding along the path is aligned with the MITRE ATT&CK Enterprise Matrix:
- **Initial Access (`TA0001`)**: `T1190` (Exploit Public-Facing Application), `T1133` (External Remote Services), `T1078` (Valid Accounts).
- **Execution (`TA0002`)**: `T1059` (Command and Scripting Interpreter).
- **Privilege Escalation (`TA0004`)**: `T1068` (Exploitation for Privilege Escalation).
- **Lateral Movement (`TA0008`)**: `T1021.004` (Remote Services: SSH), `T1021.001` (RDP), `T1021.002` (SMB/Admin Shares), `T1210` (Exploitation of Remote Services).
- **Impact (`TA0040`)**: `T1486` (Data Encrypted for Impact / Ransomware), `T1041` (Data Exfiltration Over C2).
- **Prerequisite Derivation**: Automatically enumerates actionable exploit prerequisites (e.g., routable perimeter IP, reachable database port, unquoted privilege path).

### 2.3 Normalized 0–100 Contextual Risk Scorer
Mathematical scoring guarantees strict `[0.0, 100.0]` bounds:
$$\text{Score} = \min\left(100.0, \max\left(0.0, (\text{Entry} + \text{Vuln} + \text{Target} + \text{Feasibility}) \times \text{Confidence Multiplier}\right)\right)$$
- **Entry-Point Exposure**: 0–25 points (Public internet entry point with active CISA KEV exploitation = 25 pts; public without KEV = 18 pts; internal = 8 pts).
- **Path Vulnerability Exploitability**: 0–35 points (CVSS >= 9.0 or CISA KEV = 35 pts; CVSS >= 7.0 = 25 pts; CVSS >= 4.0 = 15 pts).
- **Target Crown Jewel Criticality**: 0–25 points (`CRITICAL` = 25 pts, `HIGH` = 18 pts, `MEDIUM` = 10 pts, `LOW` = 5 pts).
- **Path Feasibility & Simplicity**: 0–15 points (1-hop direct exploit = 15 pts; 2-hop = 12 pts; 3-hop = 8 pts; 4+ hops = 5 pts).
- **Confidence Multiplier**:
  - `CONFIRMED`: 1.0 (verified open service banners, confirmed vulnerability matches, verified trust links).
  - `LIKELY`: 0.85 (verified service banner with inferred subnet route).
  - `POTENTIAL`: 0.60 (unconfirmed service version or inferred dependency).
- **Severity Brackets**: CRITICAL ($\ge 80.0$), HIGH ($60.0 - 79.9$), MEDIUM ($35.0 - 59.9$), LOW ($< 35.0$).

### 2.4 Prevention Recommendation Engine
Synthesizes and ranks compensating controls tailored to SMB realities (minimal downtime, low administrative overhead):
- `VIRTUAL_PATCH`: Deploy reverse proxy / WAF inspection rules targeting known CVEs in front of legacy SMB applications.
- `NETWORK_SEGMENTATION`: Enforce micro-segmentation rules denying DMZ-to-database direct connectivity.
- `MFA_ACCESS_CONTROL`: Mandate MFA and disable password authentication on SSH and RDP.
- `SERVICE_HARDENING`: Disable server disclosure banners, enforce TLS 1.3 ciphers.
- `LOGGING_MONITORING`: Enable centralized telemetry and audit logging on critical targets.
- **Priority Ranking Formula**:
  $$\text{Utility} = (\text{Risk Reduction} \times 4) + (\text{Complexity} \times 3) + (\text{SMB Operational Impact} \times 3)$$
  Sorted descending to yield 1-based actionable ranks (`priority_rank: 1, 2, 3...`).

---

## 3. Database & Schema Enhancements

### Alembic Migration: `007_enhance_attack_path_engine`
1. Extended `attack_paths` table with:
   - `severity`, `confidence`, `title`, `description`, `path_narrative`, `graph_data` (JSON), `mitre_tactics`, `mitre_techniques`, `prerequisites`, `evidence_references`, `status`.
2. Created `asset_trust_relationships` table:
   - Tracks explicit, evidence-backed inter-asset communication routes with tenant scoping and foreign key cascading.
3. Created `prevention_recommendations` table:
   - Stores prioritized mitigations linked to specific attack paths and assets.
4. Created `attack_path_analysis_jobs` table:
   - Tracks asynchronous background job execution metrics (`paths_discovered_count`, `recommendations_count`, `completed_at`).

---

## 4. Frontend Interactive Dashboard

Located at `frontend/src/pages/AttackPathsPage.tsx` and routed via `/attack-paths`:
- **Summary KPI Cards**: Real-time aggregation of Total Paths, Critical Paths, Crown Jewels at Risk, Compensating Controls Implemented, and Average Risk Score.
- **Visual Attack Graph**: Custom interactive node-and-directed-edge visualizer distinguishing Internet Adversary (red), Entry Points (amber ring), Pivot Nodes (blue hex), and Crown Jewels (crimson crown/database).
- **Kill-Chain Narrative & MITRE Breakdown**: Step-by-step plain text walkthrough, MITRE ATT&CK technique cards, and prerequisite checklists.
- **Compensating Controls View**: Ranked table with Risk Reduction, Complexity, and SMB Impact badges, with one-click status transitions (`PROPOSED` $\rightarrow$ `ACCEPTED` $\rightarrow$ `IMPLEMENTED` $\rightarrow$ `DISMISSED`).
- **Trust Relationships Manager**: Interactive modal to register verified inter-host trust links.

---

## 5. Automated Verification Results

### 5.1 Backend Pytest Suite (PostgreSQL 16)
- **Command**: `pytest backend/tests/test_attack_paths.py -v`
- **Result**: `13 passed, 2 warnings in 4.40s` (100% Pass)
- **Key Test Cases**:
  - `test_risk_scoring_bounds_and_factors`: Verified mathematical bounds and factor contribution.
  - `test_mitre_attack_mapping`: Verified T1190, T1133, T1021.004, T1210, T1486 mapping.
  - `test_prevention_recommendation_ranking`: Verified rank ordering and Virtual Patch synthesis.
  - `test_graph_traversal_multi_hop_evidence_backed`: Verified multi-hop discovery on PostgreSQL.
  - `test_no_invented_lateral_movement_without_evidence`: Verified zero hallucination across disconnected assets.
  - `test_attack_path_service_run_analysis_sync`: Verified database persistence and audit log creation.
  - `test_api_attack_paths_overview_and_list`: Verified REST API and pagination.
  - `test_api_attack_path_status_transition_and_audit`: Verified status lifecycle and audit records.
  - `test_api_prevention_recommendations`: Verified recommendations API and status update.
  - `test_api_trust_relationships_lifecycle`: Verified CRUD for verified trust relationships.
  - `test_multi_tenant_isolation`: Verified Tenant B cannot access Tenant A records (404/empty).
  - `test_rbac_permissions_enforcement`: Verified Viewer cannot write/mutate path state (403 Forbidden).
  - `test_celery_task_attack_path_analysis`: Verified background worker task completes with status `COMPLETED`.

### 5.2 Frontend Vitest Suite
- **Command**: `npm --prefix frontend test -- tests/attack_paths.test.tsx --run`
- **Result**: `4 passed (4)` (100% Pass)
- **Full Suite**: `npm --prefix frontend test -- --run` $\rightarrow$ `27 passed (27)` across 6 suites.

### 5.3 Vite Production Build
- **Command**: `npm --prefix frontend run build`
- **Result**: Zero TypeScript or JSX errors, bundle generated in 3.02s.

---

## 6. Phase 4 Sign-Off Gate

All Phase 4 requirements are complete, verified against PostgreSQL 16 on port 54320, Redis 8, Celery background worker, and the React frontend dashboard. Development strictly stops at Phase 4 in compliance with project instructions.

