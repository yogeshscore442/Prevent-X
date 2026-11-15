@echo off
chcp 65001 >nul
title PREVENT-X Upstream Test App
cd /d "%~dp0.."
set "PORT=%1"
if "%PORT%"=="" set "PORT=8086"

echo ==============================================================================
echo            PREVENT-X UPSTREAM TARGET APPLICATION (:8086)
echo ==============================================================================
echo [*] Working Directory: %CD%
echo [*] Listening on     : http://127.0.0.1:%PORT%
echo [*] Health Endpoint  : http://127.0.0.1:%PORT%/health
echo [*] Target for       : Reverse Proxy Virtual Patching & Security Testing
echo ==============================================================================
echo.

call .venv\Scripts\activate.bat
python scripts\run_upstream_app.py --port %PORT% --host 0.0.0.0

if errorlevel 1 (
    echo.
    echo [ERROR] Upstream test application exited with error.
    pause
)
