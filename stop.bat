@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
title PREVENT-X Platform Shutdown
cd /d "%~dp0"

echo ==============================================================================
echo                 PREVENT-X PLATFORM SHUTDOWN
echo ==============================================================================
echo.

echo [*] Stopping frontend dev server (Port 5173)...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$pids = Get-NetTCPConnection -LocalPort 5173 -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess; if ($pids) { Stop-Process -Id $pids -Force -ErrorAction SilentlyContinue }" >nul 2>&1

echo [*] Stopping backend API server (Ports 8000, 8002, 8003)...
powershell -NoProfile -ExecutionPolicy Bypass -Command "8000, 8002, 8003 | ForEach-Object { $pids = Get-NetTCPConnection -LocalPort $_ -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess; if ($pids) { foreach ($p in $pids) { $proc = Get-Process -Id $p -ErrorAction SilentlyContinue; if ($proc -and $proc.ProcessName -notmatch 'splunk') { Stop-Process -Id $p -Force -ErrorAction SilentlyContinue } } } }" >nul 2>&1

echo [*] Stopping Celery background workers...
taskkill /F /IM celery.exe >nul 2>&1

echo [*] Closing PREVENT-X console windows...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Process | Where-Object { $_.MainWindowTitle -match 'PREVENT-X' } | Stop-Process -Force -ErrorAction SilentlyContinue" >nul 2>&1

echo [+] PREVENT-X application services stopped successfully.
echo.
echo Note: PostgreSQL (Port 54320) and Redis (Port 6379) are kept running for instant startup next time.
echo If you wish to stop PostgreSQL and Redis as well, press [Y], or press any other key to keep them active.
set /p STOP_ALL="Stop PostgreSQL and Redis too? (y/N): "
if /i "!STOP_ALL!"=="y" (
    echo [*] Stopping Redis and PostgreSQL...
    taskkill /F /IM redis-server.exe >nul 2>&1
    taskkill /F /IM postgres.exe >nul 2>&1
    echo [+] PostgreSQL and Redis stopped.
)

echo.
echo Shutdown complete.
pause

