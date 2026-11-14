# ADR-005: Module Extension Points & Honest Status Introspection

## Status
Accepted

## Context
PREVENT-X will span 9 phases, introducing 12 distinct engines. A common pitfall in enterprise cybersecurity prototypes is generating "mock" or "fake" modules that pretend to scan, detect, or patch vulnerabilities without real engines. This violates strict software engineering principles.

## Decision
We established a strict contract:
1. All 12 modules are architecturally declared via `BaseSecurityModule` and registered in `module_registry`.
2. Each module explicitly states its target implementation phase (Phase 1 through Phase 8) and operational status.
3. In Phase 1, only **MOD-12 (Centralized SMB Security Management Platform)** is flagged as `OPERATIONAL`. Modules 01 through 11 are flagged as `PLANNED_PHASE`.
4. Invoking `execute_action()` on any unreleased module raises `NotImplementedError`.
5. Frontend dashboard and system health telemetry honestly display planned modules without fake vulnerability graphs, fake CVE counts, or inactive buttons.

## Consequences
- **Positive**:
  - Genuine architectural readiness for incremental rollout through Phases 2 to 9.
  - Zero deceptive functionality; total operational integrity.
- **Negative**:
  - The UI presents honest empty states and status indicators for future engines rather than pre-baked simulated charts.
