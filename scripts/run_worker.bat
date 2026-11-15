@echo off
chcp 65001 >nul
title PREVENT-X Celery Worker
cd /d "%~dp0.."

echo ==============================================================================
echo                 PREVENT-X CELERY ASYNC WORKER
echo ==============================================================================
echo [*] Working Directory: %CD%
echo [*] Broker           : redis://localhost:6379/1
echo [*] Processing Tasks : Vulnerability scans, Attack surface, Virtual patches
echo ==============================================================================
echo.

call .venv\Scripts\activate.bat
celery -A backend.app.workers.celery_app.celery_app worker --loglevel=info -P solo

if errorlevel 1 (
    echo.
    echo [ERROR] Celery worker exited with error.
    pause
)

