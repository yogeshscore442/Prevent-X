# PREVENT-X Docker Deployment Guide

## 1. Prerequisites
- Docker Engine 24.0+ or Docker Desktop
- Docker Compose v2.20+
- Minimum 2 CPU cores, 4GB RAM

---

## 2. Configuration Setup
1. Clone the repository and navigate to root:
```bash
git clone https://github.com/preventx/prevent-x.git
cd prevent-x
```

2. Generate your production environment configuration:
```bash
cp .env.example .env
```
Ensure that `SECRET_KEY`, `BOOTSTRAP_TOKEN`, and `POSTGRES_PASSWORD` are replaced with strong, cryptographically secure values.

---

## 3. Launching All Services

To build and start the entire multi-tier stack:
```bash
docker compose up --build -d
```

### Inspecting Running Services:
```bash
docker compose ps
```

Expected output:
- `preventx-postgres`: PostgreSQL 16 (healthy)
- `preventx-redis`: Redis 7 (healthy)
- `preventx-backend`: FastAPI Backend Engine (healthy)
- `preventx-frontend`: React 18 SPA (running)
- `preventx-gateway`: Nginx Reverse Proxy (running on port 80)

---

## 4. Initial Root Administrator Bootstrap

Once the containers are running and healthy, bootstrap the initial administrator account:
```bash
docker compose exec backend python -m scripts.bootstrap_admin
```
Or via HTTP POST:
```bash
curl -X POST http://localhost/api/v1/auth/bootstrap \
  -H "Content-Type: application/json" \
  -d '{
    "bootstrap_token": "preventx-bootstrap-token-prod-2026",
    "email": "admin@preventx.internal",
    "password": "AdminPasswordSecure2026!",
    "full_name": "Chief Security Officer",
    "initial_organization_name": "Primary SMB Tenant",
    "initial_organization_slug": "smb-primary"
  }'
```

---

## 5. Accessing the Platform
- **Web UI**: Open `http://localhost/` in your web browser.
- **REST API Docs**: Open `http://localhost/docs` or `http://localhost/api/v1/docs`.
- **Liveness Probe**: `http://localhost/api/v1/health`.
- **Readiness Probe**: `http://localhost/api/v1/ready`.

---

## 6. Service Management Commands

```bash
# View aggregated service logs
docker compose logs -f

# View backend logs only
docker compose logs -f backend

# Stop all services gracefully
docker compose down

# Stop and wipe persistent database volumes (Clean slate)
docker compose down -v
```

