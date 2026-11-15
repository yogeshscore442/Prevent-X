# PREVENT-X: Autonomous AI-Era Virtual Patching Platform

> **Real-time compensating cyber defense and zero-downtime virtual patching for digital enterprises and Indian SMBs.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/Frontend-React%2018%20%7C%20TypeScript-61dafb.svg)](https://reactjs.org/)
[![Tailwind CSS](https://img.shields.io/badge/Styling-Tailwind%20CSS-38bdf8.svg)](https://tailwindcss.com/)
[![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL%2016-336791.svg)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Cache%20%26%20Broker-Redis%207-dc382d.svg)](https://redis.io/)
[![Celery](https://img.shields.io/badge/Tasks-Celery%205-37814A.svg)](https://docs.celeryq.dev/)

---

## 📌 Table of Contents

1. [Overview](#-overview)
2. [Why PREVENT-X?](#-why-prevent-x)
3. [Key Capabilities & 12 Security Modules](#-key-capabilities--12-security-modules)
4. [Architecture Flow](#-architecture-flow)
5. [Tech Stack](#-tech-stack)
6. [Prerequisites](#-prerequisites)
7. [Quick Start (One-Click)](#-quick-start-one-click)
8. [Manual Setup Guide](#-manual-setup-guide)
9. [How to Use PREVENT-X (Step-by-Step)](#-how-to-use-prevent-x-step-by-step)
10. [Default Login Credentials](#-default-login-credentials)
11. [Running Tests](#-running-tests)
12. [Project Structure](#-project-structure)
13. [Troubleshooting & FAQs](#-troubleshooting--faqs)
14. [License & Acknowledgments](#-license--acknowledgments)

---

## 🌟 Overview

**PREVENT-X** is an autonomous, tenant-isolated, zero-downtime cyber defense and virtual patching platform. 

In today's digital landscape, Small and Medium Businesses (SMBs) face an asymmetric threat: automated vulnerability scanners and exploit kits attack internet-facing applications within hours of disclosure, while traditional source-code patching takes **45 to 90 days** due to development backlogs, legacy frameworks, and fear of downtime.

**PREVENT-X solves this gap**: Instead of waiting weeks to rewrite application code, PREVENT-X synthesizes, tests, and deploys **compensating virtual patches** directly into an edge reverse proxy (such as Nginx) in seconds. Malicious exploit payloads (SQLi, XSS, Path Traversal, Command Injection) are intercepted and blocked at the perimeter without requiring any changes to the underlying application.

---

## 💡 Why PREVENT-X?

* ⚡ **Immediate Remediation**: Neutralize critical vulnerabilities in seconds rather than waiting months for developer patches.
* 🛡️ **Zero Application Downtime**: Deploys hot configuration rules to the reverse proxy with zero restart disruption.
* 🔍 **Evidence-Backed Attack Paths**: Visualizes multi-hop attack graphs (DAGs) linking external assets to internal crown jewels.
* 🤖 **Autonomous Validation & Safe Rollback**: Validates patches in staging with non-destructive payloads and provides one-click atomic rollback backed by PostgreSQL advisory locks.
* 🔐 **Multi-Tenant & Role-Based**: Full data isolation per organization with granular RBAC permissions.
* 🇮🇳 **Aligned with Indian Cybersecurity Standards**: Incorporates telemetry and incident logging practices aligned with CERT-In guidelines and DPDP technical safeguards.

---

## 🧩 Key Capabilities & 12 Security Modules

PREVENT-X is built on a modular architecture divided into 12 core functional engines:

| Module ID | Module Name | What It Does |
| :--- | :--- | :--- |
| **MOD-01** | **Attack Surface Intelligence** | Discovers open ports, subdomains, TLS certificates, and HTTP headers with connection-level socket pinning (`SafePinningBackend`) to prevent SSRF and DNS rebinding. |
| **MOD-02** | **Vulnerability Mapping Engine** | Correlates discovered services with NVD CVEs, CISA KEV (Known Exploited Vulnerabilities), and EPSS exploit probability scores. |
| **MOD-03** | **Attack Path & Graph Engine** | Uses NetworkX to construct multi-hop Directed Acyclic Graphs (DAGs) mapping realistic attack vectors to MITRE ATT&CK techniques (e.g., T1190). |
| **MOD-04** | **Zero Trust Security Engine** | Continuously evaluates asset health across identity, network exposure, and vulnerability posture to compute real-time trust scores. |
| **MOD-05** | **AI Threat Intelligence** | Ingests threat feeds, tracks active CVE exploitation, and forecasts emerging risk scores. |
| **MOD-06** | **Proactive Hardening Engine** | Compiles security headers (CSP, HSTS, X-Frame-Options) and rate-limiting profiles. |
| **MOD-07** | **Behavioral Anomaly Engine** | Detects zero-day anomalies and unexpected payload spikes using Z-score statistical baseline analysis. |
| **MOD-08** | **Intelligent Virtual Patch Compiler** | Synthesizes deterministic regex rules and URI filters into native Nginx configuration blocks with automatic syntax verification (`nginx -t`). |
| **MOD-09** | **Real-Time Traffic Monitor** | Ingests edge proxy logs, tracks WAF block events, and streams real-time telemetry to the dashboard via Server-Sent Events (SSE). |
| **MOD-10** | **Automated Security Validation** | Executes automated non-destructive test probes (SQLi, XSS, Path Traversal) to verify patch effectiveness before production deployment. |
| **MOD-11** | **Response & Reliable Rollback** | Manages distributed deployment locks (PostgreSQL advisory locks) and provides instant SHA-256 verified rollback. |
| **MOD-12** | **Centralized SMB Security Center** | Delivers an executive posture score (0–100), incident management, attack path visualization, and audit trails. |

---

## 🏗️ Architecture Flow

```
                      [ External Web Traffic / Attackers ]
                                      │
                                      ▼
                      ┌─────────────────────────────────┐
                      │    Nginx Reverse Proxy & WAF    │
                      │  (MOD-08 / MOD-09 / MOD-10)     │
                      └───────────────┬─────────────────┘
                                      │
                 ┌────────────────────┴────────────────────┐
                 │                                         │
        [ Exploit Detected ]                      [ Legitimate Traffic ]
                 │                                         │
                 ▼ (403 Blocked)                           ▼ (200 OK)
         Edge Log Stream                         Upstream Web Application
                 │                                (e.g. Payment Gateway)
                 ▼
     ┌─────────────────────────────────────────────────────────────┐
     │                   PREVENT-X Core Engine                     │
     │                                                             │
     │  • FastAPI REST & SSE Services                              │
     │  • Celery Workers & Redis Queue                             │
     │  • Attack Surface Discovery (MOD-01)                        │
     │  • Vulnerability & Threat Mapping (MOD-02 & MOD-05)         │
     │  • Attack Path DAG Graph Engine (MOD-03)                    │
     │  • Zero Trust Policy Engine (MOD-04)                        │
     │  • Patch Synthesis & Staging Validator (MOD-08 & MOD-10)    │
     │  • Rollback & Distributed Locking (MOD-11)                  │
     │  • PostgreSQL Multi-Tenant Database                         │
     └──────────────────────────────┬──────────────────────────────┘
                                    │
                                    ▼
                     ┌─────────────────────────────┐
                     │  React 18 Executive Portal  │
                     │   (Dark Navy Cyber UI)      │
                     └─────────────────────────────┘
```

---

## 💻 Tech Stack

### **Backend & Asynchronous Processing**
* **Runtime**: Python 3.10+
* **Framework**: FastAPI (high-throughput asynchronous ASGI)
* **ORM & Database**: SQLAlchemy 2.0 with PostgreSQL 16
* **Database Migrations**: Alembic
* **Task Queue & Cache**: Celery 5.x & Redis 7
* **Security & Crypto**: Argon2id password hashing, PyJWT, Cryptography

### **Frontend & Visualizations**
* **Library**: React 18 with TypeScript 5
* **Build Tool**: Vite
* **Styling**: Tailwind CSS (Enterprise Dark Navy cybersecurity theme)
* **Routing**: React Router v6 with protected session guards
* **Icons & UI**: Lucide React
* **Graphs**: Interactive SVG & HTML5 Canvas DAG visualizer

### **Edge & Testing**
* **Edge Proxy**: Nginx 1.26+
* **Testing Suites**: Pytest (Backend unit & integration), Vitest & Testing Library (Frontend)

---

## ⚙️ Prerequisites

Before running PREVENT-X, ensure your machine has:
1. **Python 3.10 or higher** ([Download Python](https://www.python.org/downloads/))
2. **Node.js 18 or higher & npm** ([Download Node.js](https://nodejs.org/))
3. **PostgreSQL 16** (or use the embedded/docker instance)
4. **Redis 7** (or use the embedded/docker instance)
5. **Git** ([Download Git](https://git-scm.com/))

---

## 🚀 Quick Start (One-Click)

On Windows, PREVENT-X includes automated launcher scripts that verify dependencies, run migrations, bootstrap admin accounts, and start all services in dedicated consoles.

### 1. Clone the Repository
```bash
git clone https://github.com/yogeshscore442/Prevent-X.git
cd Prevent-X
```

### 2. Copy the Environment Template
```bash
copy .env.example .env
```

### 3. Launch All Services (Windows)
Double-click `start.bat` or run:
```cmd
start.bat
```
*(Or in PowerShell: `.\start.ps1`)*

**What `start.bat` automatically does:**
1. Verifies the Python `.venv` and creates it if missing.
2. Installs backend dependencies from `requirements.txt`.
3. Installs frontend dependencies (`npm install`).
4. Checks and starts PostgreSQL (port `54320`) and Redis (port `6379`).
5. Executes Alembic database migrations.
6. Bootstraps the default Administrator account.
7. Starts Celery background workers.
8. Starts the FastAPI backend on port `8002`.
9. Starts the Vite frontend on port `5173`.
10. Automatically launches `http://localhost:5173` in your browser!

### 4. Stopping the Services
To gracefully stop all background services, run:
```cmd
stop.bat
```
*(Or in PowerShell: `.\stop.ps1`)*

---

## 🛠️ Manual Setup Guide

If you prefer running services manually or are on Linux/macOS:

### Step 1: Backend Setup
```bash
# 1. Create and activate a Python virtual environment
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
# or: .\.venv\Scripts\activate # Windows PowerShell

# 2. Install dependencies
pip install -r backend/requirements.txt

# 3. Configure environment
cp .env.example .env

# 4. Run database migrations
cd backend
python -m alembic upgrade head
cd ..

# 5. Bootstrap default administrator
python scripts/bootstrap_admin.py

# 6. Start the API server
uvicorn backend.app.main:app --host 127.0.0.1 --port 8002 --reload
```

### Step 2: Start Celery Worker
In a separate terminal (with `.venv` active):
```bash
celery -A backend.app.workers.celery_app worker --loglevel=info -P solo
```

### Step 3: Frontend Setup
In a third terminal:
```bash
cd frontend
npm install
npm run dev
```

Open your browser at **`http://localhost:5173`**.

---

## 📖 How to Use PREVENT-X (Step-by-Step)

Here is a practical walkthrough of the end-to-end security workflow:

### Step 1: Sign In
* Navigate to `http://localhost:5173`.
* Enter the administrator credentials (see [Default Login Credentials](#-default-login-credentials)).
* You will land on the **Executive Security Center** showing the overall organization Posture Score, active alerts, and incident trends.

### Step 2: Register Digital Assets
* Go to **Asset Management** (`/assets`).
* Add your web applications, APIs, or microservices (e.g., `Payment Gateway API` at `127.0.0.1:8086`).
* Assign business criticality (`CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`).

### Step 3: Run Attack Surface Discovery
* Go to **Attack Surface Intelligence** (`/attack-surface`).
* Click **Run Controlled Discovery**.
* PREVENT-X performs safe, socket-pinned network probing to detect open ports, active services, TLS certificates, and HTTP response headers without risking SSRF.

### Step 4: Review Vulnerability Mappings
* Go to **Vulnerabilities** (`/vulnerabilities`).
* Review identified weaknesses (e.g., `CWE-89 SQL Injection` or `CWE-79 Cross-Site Scripting`).
* Inspect severity ratings, EPSS exploit likelihood scores, and CISA KEV tags.

### Step 5: Explore the Attack Path Graph
* Go to **Attack Paths** (`/attack-paths`).
* PREVENT-X automatically computes multi-hop Directed Acyclic Graphs (DAGs) linking exposed endpoints through vulnerable parameters to high-value internal assets.
* See the exact MITRE ATT&CK technique (e.g. `T1190: Exploit Public-Facing Application`) and the recommended virtual patch strategy.

### Step 6: Synthesize & Validate a Virtual Patch
* Go to **Virtual Patching** (`/virtual-patches`).
* Select a vulnerability and click **Synthesize Virtual Patch**.
* PREVENT-X generates an Nginx rule designed to inspect and reject matching exploit payloads.
* Click **Validate in Staging**: automated non-destructive test probes run to ensure the patch effectively blocks exploits without breaking normal user traffic.

### Step 7: Deploy with Human Authorization
* Click **Deploy Patch**.
* PREVENT-X acquires a distributed PostgreSQL lock, verifies Nginx configuration syntax with `nginx -t`, and reloads the proxy with zero downtime.

### Step 8: Monitor Live Traffic & Real-Time Alerts
* Go to **Monitoring** (`/monitoring`) and **Incidents**.
* PREVENT-X streams live proxy event logs and alerts. When an attacker sends an exploit payload (e.g. `' OR '1'='1`), Nginx responds with `403 Forbidden`, and an alert is instantly broadcast to the dashboard.

### Step 9: Atomic Rollback (If Ever Needed)
* If a patch needs to be revoked, click **Rollback Patch** in the Virtual Patching tab.
* PREVENT-X reverts to the previous verified SHA-256 configuration snapshot in milliseconds.

---

## 🔑 Default Login Credentials

| Role | Email | Password | Access Level |
| :--- | :--- | :--- | :--- |
| **System Super Administrator** | `admin@preventx.internal` | `AdminPasswordSecure2026!` | Full global platform administration across all tenants |
| **Demo Tenant Administrator** | `admin@alphafintech.in` | `AlphaAdminPass123!` | Complete tenant-level control (Asset management, patch deployment) |

> ⚠️ *Note: For production deployments, change these default passwords immediately in your `.env` file and via the user profile settings.*

---

## 🧪 Running Tests

PREVENT-X features comprehensive automated test coverage for backend APIs, multi-tenant isolation, security validation, and frontend components.

### 1. Run Backend Security & Integration Tests
```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests -v
```
**Key test suites verified:**
* `test_security.py`: Argon2id hashing, session token invalidation, and rate limiting.
* `test_tenant_isolation.py`: Cross-tenant penetration tests ensuring complete data isolation.
* `test_attack_surface.py`: Controlled discovery and socket-pinning safety.
* `test_virtual_patching.py`: Patch synthesis, staging validation, and atomic rollback.
* `test_end_to_end_security_workflow.py`: Comprehensive 17-step end-to-end integration test.

### 2. Run Frontend Tests
```bash
cd frontend
npm test
```

### 3. Production Build Verification
```bash
cd frontend
npm run build
```

---

## 📁 Project Structure

```
PREVENT-X/
├── backend/
│   ├── alembic.ini                   # Alembic configuration
│   ├── requirements.txt              # Pinned Python dependencies
│   ├── app/
│   │   ├── main.py                   # FastAPI application entrypoint
│   │   ├── api/v1/                   # REST API routes (auth, assets, patches, etc.)
│   │   ├── core/                     # Configuration settings, logging, exceptions
│   │   ├── database/                 # SQLAlchemy database session & engine
│   │   ├── models/                   # Database ORM entities
│   │   ├── schemas/                  # Pydantic data schemas
│   │   ├── repositories/             # Tenant-scoped data access repositories
│   │   ├── services/                 # Core domain business logic
│   │   ├── security/                 # Argon2id, JWT, and permission guards
│   │   ├── workers/                  # Celery application and task definitions
│   │   └── modules/                  # 12 Core Security Modules (MOD-01 to MOD-12)
│   │       ├── attack_surface/       # MOD-01: Asset discovery & port scanning
│   │       ├── vulnerability/        # MOD-02: CVE/CWE weakness mapping
│   │       ├── attack_path/          # MOD-03: Attack graph traversal (DAG)
│   │       ├── zero_trust/           # MOD-04: Continuous trust scoring
│   │       ├── virtual_patch/        # MOD-08: Nginx patch compiler
│   │       ├── monitoring/           # MOD-09: Log ingestion & SSE streaming
│   │       ├── security_validation/  # MOD-10: Automated staging validation
│   │       └── ...
│   ├── migrations/                   # Database version migration scripts
│   └── tests/                        # Comprehensive Pytest test suites
├── frontend/
│   ├── package.json                  # Frontend dependencies
│   ├── vite.config.ts                # Vite bundler configuration & proxy
│   ├── tailwind.config.js            # Dark Navy cybersecurity design system
│   └── src/
│       ├── main.tsx                  # React entrypoint
│       ├── contexts/                 # AuthContext and tenant state
│       ├── pages/                    # UI Pages (Dashboard, Assets, Patches, etc.)
│       ├── components/               # Reusable UI widgets and navigation
│       ├── services/                 # Axios API client with CSRF protection
│       └── types/                    # TypeScript interfaces
├── docs/                             # Architecture diagrams, specifications & demo guide
│   ├── DEMO_GUIDE.md                 # Step-by-step 15-minute evaluation guide
│   ├── DEPLOYMENT_GUIDE.md           # Production deployment instructions
│   └── PREVENT_X_FINAL_PROJECT_REPORT.md  # Comprehensive engineering report
├── scripts/                          # Utility & automation scripts
│   ├── bootstrap_admin.py            # Root admin initialization script
│   ├── run_backend.bat               # Backend startup script
│   ├── run_frontend.bat              # Frontend startup script
│   └── run_worker.bat                # Celery worker startup script
├── start.bat                         # One-click Windows platform launcher
├── start.ps1                         # PowerShell platform launcher
├── stop.bat                          # One-click platform shutdown
├── stop.ps1                          # PowerShell shutdown script
├── docker-compose.yml                # Multi-container orchestration
├── .env.example                      # Sample environment variables
├── .gitignore                        # Git ignore rules
├── LICENSE                           # MIT License
└── README.md                         # Main project documentation
```

---

## ❓ Troubleshooting & FAQs

### Q: Port 8000 or 8002 is already in use
**Answer**: Run `stop.bat` to terminate any hanging background processes, or edit `BACKEND_PORT` inside `start.bat` (defaults to `8002`).

### Q: Database connection error on startup
**Answer**: Make sure PostgreSQL is running on port `54320` (as configured in `.env`). If you are running your own PostgreSQL instance on the default port `5432`, update `DATABASE_URL` in `.env`.

### Q: Redis connection refused
**Answer**: Ensure Redis is running on port `6379`. You can verify by executing `redis-cli ping` or running `start.bat`, which launches the embedded Redis service.

### Q: How are false positives prevented during virtual patching?
**Answer**: PREVENT-X runs a staging validation suite (MOD-10) before any patch is deployed to production. Non-destructive probes test both malicious and legitimate benign traffic to ensure legitimate requests are never blocked.

---

## 📄 License & Acknowledgments

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for complete details.

### Acknowledgments
* **NASSCOM Applied Research Bridge 2.0** — Problem Statement 5 (PS-05).
* Developed by **Yogesh** ([@yogeshscore442](https://github.com/yogeshscore442)).
* Built with open-source tools: FastAPI, React, Tailwind CSS, PostgreSQL, Redis, Celery, and Nginx.

---

<p align="center">
  <b>PREVENT-X</b> — Autonomous, Resilient & Zero-Downtime Cyber Defense for Digital Enterprises.
</p>
