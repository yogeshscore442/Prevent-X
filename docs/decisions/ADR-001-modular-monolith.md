# ADR-001: Selection of Modular Monolith Architecture

## Status
Accepted

## Context
PREVENT-X addresses NASSCOM Problem Statement 5 for Indian SMBs. The platform will eventually feature 12 advanced cybersecurity engines (vulnerability mapping, virtual patching, attack path analysis, zero-trust enforcement, etc.). We needed to decide between an initial distributed microservices architecture and a modular monolithic architecture.

## Decision
We chose a **modular monolithic architecture** for Phase 1.
Individual engines are segregated into dedicated domain modules in `backend/app/modules/`, communicating across well-defined interfaces (`BaseSecurityModule`), common repositories, and standardized database schemas.

## Consequences
- **Positive**:
  - Dramatically lower operational and maintenance overhead for SMB deployment.
  - Zero inter-service network latency or distributed transaction complexities.
  - Simplified continuous integration, testing, and unified database migrations.
  - Direct refactoring path: individual modules can later be extracted into independent microservices or sidecar proxies when high traffic necessitates horizontal scaling.
- **Negative**:
  - Deployment units are shared; updating one module in production requires re-deploying the unified backend container.
