# Local Workstation Setup Guide (Non-Docker Developer Environment)

For local development and automated testing on workstations without Docker:

---

## 1. Prerequisites
- **Python**: 3.10+
- **Node.js**: v18+ or v20+ or v22+
- **Git**

---

## 2. Backend Setup

1. Create and activate a Python virtual environment:
```bash
# Windows PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

2. Install pinned dependencies:
```bash
pip install -r backend/requirements.txt
```

3. Configure local environment file:
Ensure `.env` exists in the project root:
```ini
ENVIRONMENT=development
DEBUG=true
APP_NAME=PREVENT-X
DATABASE_URL=sqlite:///./preventx.db
SECRET_KEY=preventx-local-dev-secret-key-at-least-32-bytes-long!
BOOTSTRAP_TOKEN=preventx-admin-bootstrap-token-2026
```

4. Run database migrations:
```bash
cd backend
python -m alembic upgrade head
cd ..
```

5. Bootstrap initial administrator:
```bash
python scripts/bootstrap_admin.py
```

6. Start FastAPI development server:
```bash
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```
Backend API will be live at `http://127.0.0.1:8000`.
Swagger docs will be at `http://127.0.0.1:8000/api/v1/docs`.

---

## 3. Frontend Setup

1. Navigate to `frontend/` directory and install packages:
```bash
cd frontend
npm install
```

2. Run frontend development server:
```bash
npm run dev
```
Frontend will be available at `http://localhost:5173`.
Vite is pre-configured with a reverse proxy routing `/api` requests to `http://localhost:8000`.

---

## 4. Running Automated Tests

```bash
# Backend pytest suite (23 tests: auth, RBAC, tenant isolation, DB, audit)
python -m pytest backend/tests -v

# Frontend vitest suite
cd frontend
npm test
```

