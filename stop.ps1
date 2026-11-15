# PREVENT-X PowerShell Quick Stopper
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "==============================================================================" -ForegroundColor Yellow
Write-Host "                 PREVENT-X PLATFORM SHUTDOWN" -ForegroundColor Yellow
Write-Host "==============================================================================" -ForegroundColor Yellow

Write-Host "[*] Stopping Frontend dev server (Port 5173)..." -ForegroundColor Gray
$frontendPids = Get-NetTCPConnection -LocalPort 5173 -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess
if ($frontendPids) { Stop-Process -Id $frontendPids -Force -ErrorAction SilentlyContinue }

Write-Host "[*] Stopping Backend API server (Port 8002)..." -ForegroundColor Gray
$backendPids = Get-NetTCPConnection -LocalPort 8002 -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess
if ($backendPids) {
    foreach ($p in $backendPids) {
        $proc = Get-Process -Id $p -ErrorAction SilentlyContinue
        if ($proc -and $proc.ProcessName -notmatch 'splunk') { Stop-Process -Id $p -Force -ErrorAction SilentlyContinue }
    }
}

Write-Host "[*] Stopping Celery background worker..." -ForegroundColor Gray
Get-Process celery -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host "[*] Closing PREVENT-X console windows..." -ForegroundColor Gray
Get-Process | Where-Object { $_.MainWindowTitle -match "PREVENT-X" } | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[+] PREVENT-X application services have been stopped successfully." -ForegroundColor Green
Write-Host "Note: PostgreSQL (Port 54320) and Redis (Port 6379) remain active for instant next startup." -ForegroundColor Gray

