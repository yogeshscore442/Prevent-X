# PREVENT-X
### AI-Era Virtual Patching for Security Protection of Indian SMB Digital Businesses
**NASSCOM Applied Research Bridge 2.0 — Problem Statement 5 (PS-05)**  
*Phase 1: Enterprise-Grade Foundation & Architecture*

---

## 1. Executive Summary & Problem Context

Small and Medium Businesses (SMBs) in India form the backbone of the digital economy but face acute cybersecurity operational bottlenecks:
- **Severe cybersecurity staffing shortages** (frequently zero dedicated SecOps personnel).
- **Extreme cost sensitivity** prohibiting complex, multi-million rupee hardware appliances.
- **Fragmented, legacy technology stacks** across heterogeneous hosting environments.
- **Low tolerance for downtime** or false-positive request blocking.
- **Intermittent connectivity** across Tier-2/Tier-3 regional networks.

**PREVENT-X** is an independent, enterprise-grade virtual patching platform engineered to protect Indian SMB web applications, APIs, and digital assets. By synthesizing precise compensating controls at the reverse proxy, gateway, and middleware tiers, PREVENT-X neutralizes discovered vulnerabilities without code modifications, application downtime, or operational disruption.

> **Current Implementation Phase**: This codebase delivers **ONLY Phase 1 (Enterprise-Grade Foundation & Architecture)**. Future engines (vulnerability scanning, automated virtual patch generation, attack path analysis) are architecturally defined with typed extension boundaries and will be implemented incrementally across Phases 2 through 9.

---

## 2. Technology Stack & Pinned Versions

| Layer | Component | Version | Rationale |
|:---|:---|:---:|:---|
| **Frontend** | React.js | `^18.2.0` | Industry-standard declarative UI library |
| | TypeScript | `^5.4.2` | Strict compile-time type safety across all interfaces |
| | Vite | `^5.1.6` | High-performance bundler and fast HMR development server |
| | Tailwind CSS | `^3.4.1` | Utility-first dark navy enterprise cybersecurity styling |
| | React Router | `^6.22.3` | Client-side routing with protected session guards |
| | Axios | `^1.6.8` | Promise-based HTTP client with CSRF and auth interceptors |
| | Lucide React | `^0.359.0` | Clean, accessible iconography |
| **Backend** | Python | `3.10.11` | High-stability enterprise runtime |
| | FastAPI | `0.110.3` | High-throughput asynchronous ASGI web framework |
| | Pydantic | `2.14.3` | High-speed data parsing and validation |
| | SQLAlchemy | `2.0.57` | Enterprise ORM with typed declarative models |
| | Alembic | `1.20.1` | Database schema versioning and migration management |
| | Argon2-cffi | `25.1.0` | Modern Argon2id password hashing (PHC winner) |
| | PyJWT | `2.15.1` | Cryptographic JWT token signing and verification |
| **Storage & Caching** | PostgreSQL | `16-alpine` | ACID-compliant relational multi-tenant database |
| | Redis | `7-alpine` | High-throughput in-memory cache and Celery broker |
| | Celery | `5.7.0` | Asynchronous task queue for background jobs |
| **Edge Infrastructure** | Nginx | `alpine-slim` | Hardened edge reverse proxy, rate limiter, and security headers |
| | Docker | Compose v2 | Containerized micro-tier deployment |
| **Testing** | Pytest | `8.4.2` | Comprehensive backend integration and security test suite |
| | Vitest | `1.6.1` | Fast unit and component test runner for React |
| | Testing Library | `14.2.1` | DOM testing for user interaction workflows |

---

## 3. Project Directory Structure

```
PREVENT-X/
  ├── backend/
  │   ├── app/
  │   │   ├── api/v1/endpoints/   # Versioned REST API endpoints (auth, orgs, users, assets, etc.)
  │   │   ├── core/               # Configuration (Pydantic Settings), logging, exceptions
  │   │   ├── database/           # Engine connection, GUID type decorator, Base declarative
  │   │   ├── models/             # SQLAlchemy ORM models (Users, Orgs, Assets, Sessions, Audit)
  │   │   ├── schemas/            # Pydantic v2 validation and response schemas
  │   │   ├── repositories/       # Tenant-scoped data access repositories
  │   │   ├── services/           # Domain business logic layer (Auth, Bootstrap, Assets, Orgs)
  │   │   ├── security/           # Argon2id, token cryptographic utilities, RBAC dependencies
  │   │   ├── middleware/         # Security headers, sliding-window rate limiting, CSRF
  │   │   ├── integrations/       # Redis client with resilient connection pooling
  │   │   ├── workers/            # Celery application and background tasks
  │   │   ├── modules/            # Interfaces, registry, and contracts for Modules 01-12
  │   │   └── main.py             # FastAPI application entrypoint
  │   ├── migrations/             # Alembic migration environment and versions
  │   ├── tests/                  # Pytest test suite (23 integration & security tests)
  │   └── requirements.txt        # Pinned Python dependencies
  ├── frontend/
  │   ├── src/
  │   │   ├── app/                # Root App component and providers
  │   │   ├── contexts/           # AuthContext managing user, tenant context, and permissions
  │   │   ├── layouts/            # AppLayout (Sidebar, Tenant Switcher, Header, Breadcrumbs)
  │   │   ├── pages/              # 10 Real Pages (Dashboard, Assets, Orgs, Users, Roles, Audit, etc.)
  │   │   ├── routes/             # AppRoutes with ProtectedRoute guards
  │   │   ├── services/           # Axios instance with CSRF and auth interceptors
  │   │   ├── types/              # TypeScript interface definitions
  │   │   └── styles/             # Tailwind CSS dark navy cybersecurity styling
  │   ├── tests/                  # Vitest component test suites
  │   ├── package.json            # Pinned Node dependencies
  │   └── vite.config.ts          # Vite configuration with API reverse proxy
  ├── infrastructure/
  │   ├── docker/                 # Production Dockerfiles (Backend, Frontend)
  │   ├── nginx/                  # Edge reverse proxy configuration and security headers
  │   ├── postgres/               # Database initialization SQL
  │   └── redis/                  # Hardened Redis configuration
  ├── docs/
  │   ├── architecture/           # System overview, diagrams, and module contracts
  │   ├── api/                    # Complete REST API v1 specification
  │   ├── database/               # ER diagrams and schema documentation
  │   ├── security/               # Security design, Argon2id, session lifecycle, tenant isolation
  │   ├── deployment/             # Docker deployment and troubleshooting guides
  │   ├── testing/                # Testing guide and verified test execution results
  │   ├── decisions/              # Architectural Decision Records (ADR-001 through ADR-005)
  │   └── limitations/            # Known limitations and Phase 1 scope boundaries
  ├── scripts/
  │   ├── bootstrap_admin.py      # CLI root administrator bootstrap script
  │   └── verify_phase1.py        # Automated end-to-end verification harness
  ├── docker-compose.yml          # Multi-tier container orchestration
  ├── .env.example                # Template configuration with all environment variables
  ├── .gitignore                  # Git ignore rules
  └── README.md                   # Primary system documentation
```

---

## 4. Quick Start & Execution Guide

### Option A: Running via Docker Compose (Recommended)

1. **Clone repository and configure environment**:
   ```bash
   cp .env.example .env
   ```

2. **Build and launch all services**:
   ```bash
   docker compose up --build -d
   ```

3. **Verify container health**:
   ```bash
   docker compose ps
   ```

4. **Bootstrap initial administrator**:
   ```bash
   docker compose exec backend python scripts/bootstrap_admin.py
   ```

5. **Access Application**:
   - **Frontend UI**: `http://localhost/`
   - **Interactive API Docs (Swagger)**: `http://localhost/docs` or `http://localhost/api/v1/docs`
   - **Default Credentials**: `admin@preventx.internal` / `AdminPasswordSecure2026!`

---

### Option B: Running on Local Workstation (Non-Docker)

1. **Backend Setup**:
   ```powershell
   # Activate virtual environment
   .\.venv\Scripts\Activate.ps1

   # Install dependencies
   pip install -r backend/requirements.txt

   # Run database migrations
   cd backend
   python -m alembic upgrade head
   cd ..

   # Bootstrap initial administrator
   python scripts/bootstrap_admin.py

   # Start backend API server
   uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
   ```

2. **Frontend Setup**:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
   Open `http://localhost:5173` in your browser.

---

## 5. Automated Testing & Verification

Testing is mandatory and fully automated.

### Backend Pytest Suite (23 Tests Passed)
```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests -v
```
Tests verify:
- Argon2id password hashing and verification.
- Administrator onboarding via bootstrap token.
- User login, logout, and database session revocation.
- Role-based authorization and granular permission boundaries.
- **Strict Multi-Tenant Isolation**: Explicit cross-tenant read attacks, deletion attacks, update attacks, and tenant header spoofing attempts.
- Authorized asset lifecycle management.
- Cryptographic audit trail logging.
- System health and readiness probes.
- Double-submit CSRF cookie protection.
- Sliding-window rate limiting.

### Frontend Vitest Suite
```bash
cd frontend
npm test
```

### Frontend TypeScript Compilation & Production Build
```bash
cd frontend
npm run build
```

---

## 6. Phase 1 Acceptance Checklist

- [x] **Project Structure**: Modular, clean, maintainable architecture following enterprise guidelines.
- [x] **Frontend Operational**: React 18 + TypeScript + Vite + Tailwind CSS with dark navy enterprise styling.
- [x] **Backend Operational**: FastAPI + Pydantic v2 + SQLAlchemy 2.0 with versioned `/api/v1` endpoints.
- [x] **Database Engine & Migrations**: PostgreSQL DDL schema with UUID primary keys and Alembic migration tracking.
- [x] **Secure Authentication**: Argon2id password hashing, `HttpOnly` SameSite cookies, session tokens, and instant revocation.
- [x] **CSRF & Rate Limiting**: Double-submit CSRF cookie enforcement and sliding-window rate limiters.
- [x] **Role-Based Access Control**: Built-in roles (`SUPER_ADMIN`, `ORG_ADMIN`, `SECURITY_ANALYST`, `AUDITOR`, `VIEWER`) and 11 granular permissions.
- [x] **Multi-Tenant SMB Isolation**: Tenant scoping on all queries; explicit cross-tenant penetration tests passing.
- [x] **Managed Asset Foundation**: Authorized digital exposure inventory for Indian SMBs.
- [x] **Immutable Audit Trail**: Structured database audit log of all security and administrative operations.
- [x] **Health & Readiness**: `/api/v1/health` and `/api/v1/ready` probes verifying database latency and cache status.
- [x] **Honest Module Architecture**: All 12 future cybersecurity engines declared with interfaces and status telemetry without fake features.
- [x] **Docker Infrastructure**: Production `docker-compose.yml`, multi-stage Dockerfiles, and hardened Nginx reverse proxy.
- [x] **Automated Tests**: 100% pass rate across backend and frontend test suites.
- [x] **Technical Documentation**: Comprehensive architecture, API specs, ER diagrams, security designs, and ADRs.

---

## 7. Roadmap: Future Implementation Phases

PREVENT-X will be developed incrementally through nine phases. Phase 1 provides the foundation:

- **Phase 2**: Attack Surface Intelligence Engine (MOD-01)
- **Phase 3**: Advanced Vulnerability Mapping Engine (MOD-02)
- **Phase 4**: Attack Path Analysis & Zero Trust Engines (MOD-03, MOD-04)
- **Phase 5**: AI Threat Intelligence & Hardening Engines (MOD-05, MOD-06)
- **Phase 6**: Intelligent Virtual Patching & Zero-Day Resilience Engines (MOD-07, MOD-08)
- **Phase 7**: Real-Time Traffic Monitoring & Security Validation Engines (MOD-09, MOD-10)
- **Phase 8**: Automated Response & Reliable Rollback Engine (MOD-11)
- **Phase 9**: Final Hardening, Benchmarking & Production Launch
