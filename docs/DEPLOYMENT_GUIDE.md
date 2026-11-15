# PREVENT-X: Production Deployment & Operations Guide
**Platform Version**: 1.0.0 (Phase 9 Release)  
**Operating Systems**: Linux (Ubuntu 22.04 LTS / Debian 12 / RHEL 9), Windows (Windows 10/11, Server 2022)  
**Target Architecture**: Single-node or distributed multi-tier deployment  

---

## 1. System Prerequisites

### 1.1 Hardware Specifications
- **Minimum**: 2 vCPUs, 4 GB RAM, 20 GB SSD storage.
- **Recommended (Production SMB Gateway)**: 4 vCPUs, 8 GB RAM, 50 GB SSD storage.

### 1.2 Required Software Dependencies
| Component | Minimum Version | Verified Version | Notes |
| :--- | :--- | :--- | :--- |
| **Python** | 3.10+ | 3.10.11 | Required for FastAPI backend and Celery workers |
| **PostgreSQL** | 15+ | 16.0 | Primary relational store (port 5432 or custom 54320) |
| **Redis** | 6.2+ | 7.2 / 8.10.3 | Cache, Celery broker, and SSE event streaming |
| **Nginx** | 1.24+ | 1.26.2 | Reverse proxy gateway & virtual patch runtime engine |
| **Node.js** | 18 LTS+ | 20.x | Required for building the React/Vite frontend |
| **Docker & Compose** | 24+ / 2.20+ | Docker Compose v2 | Optional: for containerized deployment |

---

## 2. Environment Configuration & Secrets Hygiene

Copy `.env.example` to `.env` in the project root. Never commit production `.env` files to source control.

```bash
# Application Mode
ENVIRONMENT=production
DEBUG=false
APP_NAME=PREVENT-X
APP_VERSION=1.0.0
API_V1_PREFIX=/api/v1

# Relational Database Connection (PostgreSQL 16)
DATABASE_URL=postgresql://preventx_user:your_secure_password@localhost:54320/preventx_db

# Redis Cache & Message Broker
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/1
CELERY_RESULT_BACKEND=redis://localhost:6379/2

# Cryptographic Keys & JWT Security
# Generate using: python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=9a8f3b4c1d2e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_DAYS=7

# Initial System Bootstrap Token (Single-Use)
BOOTSTRAP_TOKEN=preventx-initial-bootstrap-key-2026

# Cookie Security & CSRF
COOKIE_SECURE=true
COOKIE_SAMESITE=lax
CSRF_PROTECTION_ENABLED=true

# Reverse Proxy Gateway Runtime
NGINX_BINARY_PATH=infrastructure/bin/nginx/nginx-1.26.2/nginx.exe
NGINX_PREFIX_PATH=infrastructure/bin/nginx/nginx-1.26.2/
NGINX_CONFIG_DIR=infrastructure/bin/nginx/conf/
DEFAULT_PROXY_PORT=8085
```

---

## 3. Database Initialization & Alembic Migrations

PREVENT-X uses Alembic for structured, reproducible database schema migrations.

### 3.1 Initialize PostgreSQL Database
Ensure PostgreSQL is running and create the user and database:
```sql
CREATE USER preventx_user WITH PASSWORD 'your_secure_password';
CREATE DATABASE preventx_db OWNER preventx_user;
GRANT ALL PRIVILEGES ON DATABASE preventx_db TO preventx_user;
```

### 3.2 Run Migrations
Execute all 11 schema migrations from `001` through `011`:
```powershell
# Windows PowerShell
$env:PYTHONPATH="."
$env:DATABASE_URL="postgresql://preventx_user:your_secure_password@localhost:54320/preventx_db"
.venv\Scripts\alembic upgrade head
```
```bash
# Linux / macOS Bash
export PYTHONPATH="."
export DATABASE_URL="postgresql://preventx_user:your_secure_password@localhost:5432/preventx_db"
.venv/bin/alembic upgrade head
```

**Migration Sequence**:
1. `001_initial_schema`: Core organizations, users, RBAC roles, permissions, audit logs.
2. `002_managed_assets`: Managed asset inventory, IP and domain assets.
3. `003_attack_surface`: Passive and active attack surface scans, DNS, TLS records.
4. `004_vulnerabilities`: Vulnerability findings, NVD CVE records, CISA KEV catalog.
5. `005_attack_paths`: Attack path DAGs, choke points, prevention recommendations.
6. `006_zero_trust`: Zero trust evaluations, trust boundaries, behavioral anomalies.
7. `007_virtual_patching`: Virtual patch rules, rule versions, compiled deployments.
8. `008_security_validation`: Automated validation jobs, test results, canary policies.
9. `009_distributed_locking`: PostgreSQL advisory locks for deployment concurrency.
10. `010_rollback_orchestration`: Rollback records, configuration snapshots, SHA-256 hashes.
11. `011_monitoring_security_center`: Real-time security events, incidents, timeline entries.

---

## 4. Native Service Execution (Step-by-Step)

### 4.1 Start Redis Server
```powershell
# Windows (Standalone binary)
.\infrastructure\bin\redis\redis-server.exe --port 6379
```
```bash
# Linux
sudo systemctl enable --now redis-server
```

### 4.2 Start Celery Asynchronous Worker
The background worker executes discovery scans, vulnerability synchronization, and anomaly detection:
```powershell
# Windows (solo pool required on Windows)
$env:PYTHONPATH="."
$env:DATABASE_URL="postgresql://preventx_user:your_secure_password@localhost:54320/preventx_db"
.venv\Scripts\celery -A backend.app.workers.celery_app.celery_app worker --loglevel=info -P solo
```
```bash
# Linux (prefork pool)
export PYTHONPATH="."
export DATABASE_URL="postgresql://preventx_user:your_secure_password@localhost:5432/preventx_db"
.venv/bin/celery -A backend.app.workers.celery_app.celery_app worker --loglevel=info -c 4
```

### 4.3 Start FastAPI ASGI Backend Server
```powershell
# Windows
$env:PYTHONPATH="."
$env:DATABASE_URL="postgresql://preventx_user:your_secure_password@localhost:54320/preventx_db"
.venv\Scripts\uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --workers 2
```
```bash
# Linux
export PYTHONPATH="."
export DATABASE_URL="postgresql://preventx_user:your_secure_password@localhost:5432/preventx_db"
.venv/bin/uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### 4.4 Build & Serve Frontend Application
```bash
# Install frontend dependencies & build bundle
cd frontend
npm install
npm run build

# Serve production dist directory
npm run preview -- --port 3000 --host 0.0.0.0
```

---

## 5. Containerized Deployment via Docker Compose

For production environments with Docker Engine and Docker Compose installed:

```bash
# 1. Build and launch all services in detached mode
docker compose up -d --build

# 2. Verify container health status
docker compose ps

# 3. Stream combined application logs
docker compose logs -f backend worker
```

**Services Launched**:
- `preventx-postgres` (PostgreSQL 16)
- `preventx-redis` (Redis 7)
- `preventx-backend` (FastAPI API on internal port 8000)
- `preventx-celery-worker` (Background Worker)
- `preventx-frontend` (Static SPA bundle)
- `preventx-gateway` (Nginx on host port 80 routing traffic)

---

## 6. System Bootstrap & Initial Organization Setup

Upon first startup, initialize the primary tenant using the single-use bootstrap endpoint:

```bash
curl -X POST http://localhost:8000/api/v1/bootstrap \
  -H "Content-Type: application/json" \
  -H "X-Bootstrap-Token: preventx-initial-bootstrap-key-2026" \
  -d '{
    "org_name": "Alpha Fintech India Private Limited",
    "admin_email": "admin@alphafintech.in",
    "admin_password": "StrongPassword123!",
    "admin_full_name": "Principal Security Officer"
  }'
```

After bootstrap, authenticate via `/api/v1/auth/login` to obtain session tokens.

---

## 7. Production Security Hardening Checklist

- [x] **Change Default Passwords**: Replace default database passwords and `SECRET_KEY` with cryptographically secure random values.
- [x] **Invalidate Bootstrap Token**: Clear or rotate `BOOTSTRAP_TOKEN` after first-tenant onboarding.
- [x] **Enforce HTTPS / TLS 1.3**: Terminate TLS at the edge reverse proxy using valid Let's Encrypt or enterprise certificates.
- [x] **CORS Origin Whitelist**: Restrict `ALLOWED_HOSTS` and CORS origins to verified production domain names.
- [x] **Cookie Security**: Set `COOKIE_SECURE=true` and `COOKIE_SAMESITE=lax` in production.
- [x] **Distributed Locks**: Verify PostgreSQL advisory locks are active for all deployment and rollback actions.
- [x] **Audit Log Retention**: Ensure PostgreSQL volume storage retains audit events for a minimum of 180 days (CERT-In compliance).

---

## 8. Health Checking & Verification

To verify full system operational status:

```bash
# Check Backend API & 12-Module Status
curl -s http://localhost:8000/api/v1/health | jq .

# Verify Nginx Reverse Proxy Live Status
curl -s http://localhost:8000/api/v1/virtual-patches/status | jq .

# Run Full Automated Test Suite
pytest -v backend/tests/
```
