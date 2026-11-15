# PREVENT-X PowerShell Quick Launcher
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "           PREVENT-X : AI-Era Virtual Patching Platform" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan

# 1. Start Postgres if not running
$pg = Get-NetTCPConnection -LocalPort 54320 -State Listen -ErrorAction SilentlyContinue
if (-not $pg) {
    Write-Host "[*] Starting PostgreSQL on port 54320..." -ForegroundColor Yellow
    Start-Process "$Root\infrastructure\bin\postgres\bin\postgres.exe" -ArgumentList "-D", "$Root\data\pgdata", "-p", "54320" -WindowStyle Hidden
    Start-Sleep -Seconds 3
} else {
    Write-Host "[+] PostgreSQL is running on port 54320." -ForegroundColor Green
}

# 2. Start Redis if not running
$redis = Get-NetTCPConnection -LocalPort 6379 -State Listen -ErrorAction SilentlyContinue
if (-not $redis) {
    Write-Host "[*] Starting Redis on port 6379..." -ForegroundColor Yellow
    Start-Process "$Root\infrastructure\bin\redis\redis-server.exe" -ArgumentList "--port", "6379" -WindowStyle Hidden
    Start-Sleep -Seconds 1
} else {
    Write-Host "[+] Redis is running on port 6379." -ForegroundColor Green
}

# 3. Run migrations & admin bootstrap
Write-Host "[*] Synchronizing database and administrator..." -ForegroundColor Yellow
& "$Root\.venv\Scripts\python.exe" -m alembic -c backend/alembic.ini upgrade head *>$null
& "$Root\.venv\Scripts\python.exe" "$Root\scripts\bootstrap_admin.py" *>$null
Write-Host "[+] System roles and root administrator synchronized." -ForegroundColor Green

# 4. Cleanup stale Vite and Backend instances
$stalePorts = @(5173, 8002)
foreach ($p in $stalePorts) {
    $pids = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess
    if ($pids) {
        foreach ($pidToKill in $pids) {
            $proc = Get-Process -Id $pidToKill -ErrorAction SilentlyContinue
            if ($proc -and $proc.ProcessName -notmatch 'splunk') {
                Stop-Process -Id $pidToKill -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

# 5. Start Celery Worker
$celery = Get-Process -Name "celery" -ErrorAction SilentlyContinue
if (-not $celery) {
    Write-Host "[*] Starting Celery worker in new window..." -ForegroundColor Yellow
    Start-Process "cmd.exe" -ArgumentList "/k", "call `"$Root\scripts\run_worker.bat`""
} else {
    Write-Host "[+] Celery worker is already running." -ForegroundColor Green
}

# 6. Start Backend API
Write-Host "[*] Starting Backend API on port 8002 in new window..." -ForegroundColor Yellow
Start-Process "cmd.exe" -ArgumentList "/k", "call `"$Root\scripts\run_backend.bat`" 8002"

# 7. Start Frontend UI
Write-Host "[*] Starting Frontend UI on port 5173 in new window..." -ForegroundColor Yellow
Start-Process "cmd.exe" -ArgumentList "/k", "call `"$Root\scripts\run_frontend.bat`" 8002"

# 8. Open Browser
Start-Sleep -Seconds 3
Start-Process "http://localhost:5173"

Write-Host ""
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host "                 PREVENT-X PLATFORM OPERATIONAL" -ForegroundColor Green
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host "  [+] Frontend UI          : http://localhost:5173" -ForegroundColor White
Write-Host "  [+] Backend API          : http://127.0.0.1:8002" -ForegroundColor White
Write-Host "  [+] Interactive Docs     : http://127.0.0.1:8002/api/v1/docs" -ForegroundColor White
Write-Host "  [+] PostgreSQL Database  : Port 54320" -ForegroundColor White
Write-Host "  [+] Redis Cache/Broker   : Port 6379" -ForegroundColor White
Write-Host "  [+] Celery Worker        : Active" -ForegroundColor White
Write-Host ""
Write-Host "  Default Credentials:" -ForegroundColor Cyan
Write-Host "    Email    : admin@preventx.internal" -ForegroundColor Cyan
Write-Host "    Password : AdminPasswordSecure2026!" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Green

