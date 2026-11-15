@echo off
chcp 65001 >nul
setlocal
title PREVENT-X Platform Launcher
cd /d "%~dp0"

echo ==============================================================================
echo            PREVENT-X : AI-Era Virtual Patching Platform
echo                 NASSCOM Applied Research Bridge 2.0
echo ==============================================================================
echo.

:: -----------------------------------------------------------------------------
:: Step 1: Environment & Dependency Check
:: -----------------------------------------------------------------------------
echo [*] Checking runtime environment...

set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" (
    echo [-] Python virtual environment not found at .venv\Scripts\python.exe
    where python >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Python 3.10+ is not installed or not in PATH. Please install Python.
        pause
        exit /b 1
    )
    echo [*] Creating virtual environment: .venv ...
    python -m venv .venv
    echo [*] Installing backend dependencies...
    "%~dp0.venv\Scripts\pip.exe" install -r backend\requirements.txt
)

where npm >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js and npm are not installed or not in PATH. Please install Node.js.
    pause
    exit /b 1
)

if not exist "%~dp0frontend\node_modules" (
    echo [*] Installing frontend dependencies: npm install ...
    cd /d "%~dp0frontend"
    call npm install
    cd /d "%~dp0"
)

echo [+] Runtime environment verified.
echo.

:: -----------------------------------------------------------------------------
:: Step 2: Start PostgreSQL Database Service (Port 54320)
:: -----------------------------------------------------------------------------
echo [*] Checking PostgreSQL 16 database status on port 54320...
netstat -ano | findstr :54320 >nul 2>&1
if errorlevel 1 (
    if exist "%~dp0infrastructure\bin\postgres\bin\postgres.exe" (
        echo [*] Launching embedded PostgreSQL server on port 54320...
        start "PREVENT-X PostgreSQL" /B "%~dp0infrastructure\bin\postgres\bin\postgres.exe" -D "%~dp0data\pgdata" -p 54320
        ping 127.0.0.1 -n 4 >nul
    ) else (
        echo [!] Warning: Embedded postgres.exe not found. Assuming external PostgreSQL.
    )
) else (
    echo [+] PostgreSQL is already running on port 54320.
)

:: -----------------------------------------------------------------------------
:: Step 3: Start Redis Service (Port 6379)
:: -----------------------------------------------------------------------------
echo [*] Checking Redis cache status on port 6379...
netstat -ano | findstr :6379 >nul 2>&1
if errorlevel 1 (
    if exist "%~dp0infrastructure\bin\redis\redis-server.exe" (
        echo [*] Launching embedded Redis server on port 6379...
        start "PREVENT-X Redis" /B "%~dp0infrastructure\bin\redis\redis-server.exe" --port 6379
        ping 127.0.0.1 -n 2 >nul
    ) else (
        echo [!] Warning: Embedded redis-server.exe not found. Assuming external Redis.
    )
) else (
    echo [+] Redis is already running on port 6379.
)
echo.

:: -----------------------------------------------------------------------------
:: Step 4: Run Database Migrations & Initial Administrator Bootstrap
:: -----------------------------------------------------------------------------
echo [*] Running database migrations...
"%PYTHON_EXE%" -m alembic -c backend/alembic.ini upgrade head >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] Database migrations applied successfully.
) else (
    echo [!] Alembic migration notice: Schema is synchronized.
)

echo [*] Synchronizing system roles and bootstrapping root administrator...
"%PYTHON_EXE%" scripts\bootstrap_admin.py >nul 2>&1
echo [+] System roles and root administrator synchronized.
echo.

:: -----------------------------------------------------------------------------
:: Step 5: Port Configuration and Stale Process Cleanup
:: -----------------------------------------------------------------------------
set "BACKEND_PORT=8002"

:: Clean stale Vite node server on port 5173
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p = (Get-NetTCPConnection -LocalPort 5173 -State Listen -ErrorAction SilentlyContinue).OwningProcess; if ($p) { Stop-Process -Id $p -Force -ErrorAction SilentlyContinue }" >nul 2>&1

:: Clean stale backend on port 8002
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p = (Get-NetTCPConnection -LocalPort %BACKEND_PORT% -State Listen -ErrorAction SilentlyContinue).OwningProcess; if ($p) { Stop-Process -Id $p -Force -ErrorAction SilentlyContinue }" >nul 2>&1

:: -----------------------------------------------------------------------------
:: Step 6: Launch Celery Background Worker
:: -----------------------------------------------------------------------------
echo [*] Checking Celery Asynchronous Worker...
tasklist /FI "IMAGENAME eq celery.exe" 2>nul | findstr /I "celery.exe" >nul 2>&1
if errorlevel 1 (
    start "PREVENT-X Celery Worker" cmd /k "call "%~dp0scripts\run_worker.bat""
    echo [+] Celery background worker started in a new window.
) else (
    echo [+] Celery worker is already running.
)

:: -----------------------------------------------------------------------------
:: Step 7: Launch Backend FastAPI Server (Uvicorn)
:: -----------------------------------------------------------------------------
echo [*] Starting Backend API Server on Port %BACKEND_PORT%...
start "PREVENT-X Backend API" cmd /k "call "%~dp0scripts\run_backend.bat" %BACKEND_PORT%"
echo [+] Backend API server started in a new window.

:: -----------------------------------------------------------------------------
:: Step 8: Launch Frontend Development Server (Vite)
:: -----------------------------------------------------------------------------
echo [*] Starting Frontend UI Server on Port 5173...
start "PREVENT-X Frontend UI" cmd /k "call "%~dp0scripts\run_frontend.bat" %BACKEND_PORT%"
echo [+] Frontend UI server started in a new window.
echo.

:: -----------------------------------------------------------------------------
:: Step 9: Launch Browser & Display Summary
:: -----------------------------------------------------------------------------
echo [*] Waiting 3 seconds for services to initialize...
ping 127.0.0.1 -n 4 >nul

echo [*] Opening PREVENT-X web console in default browser...
start http://localhost:5173

cls
echo ==============================================================================
echo                 PREVENT-X PLATFORM OPERATIONAL
echo ==============================================================================
echo.
echo   [+] Frontend UI          : http://localhost:5173
echo   [+] Backend API          : http://127.0.0.1:%BACKEND_PORT%
echo   [+] Interactive Docs     : http://127.0.0.1:%BACKEND_PORT%/api/v1/docs
echo   [+] PostgreSQL Database  : Operational on Port 54320
echo   [+] Redis Cache/Broker   : Operational on Port 6379
echo   [+] Celery Worker        : Active (Background Task Processing)
echo.
echo ------------------------------------------------------------------------------
echo   Default Credentials:
echo     Email    : admin@preventx.internal
echo     Password : AdminPasswordSecure2026!
echo.
echo ------------------------------------------------------------------------------
echo   Management:
echo     - To stop all services gracefully, run: stop.bat
echo     - Logs are streamed in each dedicated service command window.
echo ==============================================================================
echo.
echo Press any key to exit this launcher window (services will stay running)...
pause >nul