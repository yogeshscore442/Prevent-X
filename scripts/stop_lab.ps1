param(
    [switch]$StopAll = $false
)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent $ScriptDir
Set-Location $Root

$LogsDir = Join-Path $Root "logs"
$pidsFile = Join-Path $LogsDir "lab_pids.json"
$pidsData = @{}
if (Test-Path $pidsFile) {
    try {
        $pidsData = Get-Content $pidsFile -Raw -Encoding utf8 | ConvertFrom-Json
    } catch {}
}

Write-Host "==============================================================================" -ForegroundColor Yellow
Write-Host "               PREVENT-X : SECURITY LAB GRACEFUL SHUTDOWN" -ForegroundColor Yellow
Write-Host "==============================================================================" -ForegroundColor Yellow
Write-Host "[*] Terminating PREVENT-X runtime processes safely..." -ForegroundColor Gray
Write-Host ""

$shutdownReport = @()

function Record-Status {
    param([string]$Service, [string]$Action, [string]$Status, [string]$Color = "Green")
    $script:shutdownReport += [PSCustomObject]@{
        Service = $Service
        Action  = $Action
        Status  = $Status
        Color   = $Color
    }
}

function Terminate-ProcessById {
    param([int]$ProcessId, [string]$ServiceName = "Process")
    if ($ProcessId -le 0) { return }
    $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($proc) {
        # Terminate child processes first
        Get-CimInstance Win32_Process -Filter "ParentProcessId = $ProcessId" -ErrorAction SilentlyContinue | ForEach-Object {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        }
        Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
    }
}

# -----------------------------------------------------------------------------
# 1. Stop Frontend UI (Vite dev server on port 5173)
# -----------------------------------------------------------------------------
$fePids = Get-NetTCPConnection -LocalPort 5173 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique
$feCount = 0
if ($fePids) {
    foreach ($pidToKill in $fePids) {
        Terminate-ProcessById -ProcessId $pidToKill -ServiceName "Frontend UI"
        $feCount++
    }
}
# Stop any Vite node processes or cmd wrappers for frontend
Get-CimInstance Win32_Process | Where-Object {
    ($_.CommandLine -match "PREVENT-X" -and $_.CommandLine -match "run_frontend") -or
    ($_.CommandLine -match "vite" -and $_.CommandLine -match "frontend")
} | ForEach-Object {
    Terminate-ProcessById -ProcessId $_.ProcessId -ServiceName "Frontend CMD"
    $feCount++
}
# Close frontend console window if open
Get-Process | Where-Object { $_.MainWindowTitle -match "PREVENT-X Frontend UI" } | Stop-Process -Force -ErrorAction SilentlyContinue
if ($feCount -gt 0) {
    Record-Status "Frontend UI (Vite :5173)" "Terminated $feCount process(es)" "STOPPED" "Green"
} else {
    Record-Status "Frontend UI (Vite :5173)" "No active listener detected" "NOT RUNNING" "Gray"
}

# -----------------------------------------------------------------------------
# 2. Stop Backend API Server (Port 8002 & Uvicorn Reloaders / Multiprocessing forks)
# -----------------------------------------------------------------------------
$bePids = Get-NetTCPConnection -LocalPort 8002 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique
$beCount = 0
if ($bePids) {
    foreach ($pidToKill in $bePids) {
        Terminate-ProcessById -ProcessId $pidToKill -ServiceName "Backend API"
        $beCount++
    }
}
# Find and stop uvicorn parent reloader, multiprocessing children, and backend CMD wrappers
Get-CimInstance Win32_Process | Where-Object {
    ($_.CommandLine -match "backend\.app\.main:app") -or
    ($_.CommandLine -match "PREVENT-X" -and $_.CommandLine -match "run_backend") -or
    ($_.CommandLine -match "PREVENT-X\\\.venv" -and $_.CommandLine -match "multiprocessing\.spawn")
} | ForEach-Object {
    Terminate-ProcessById -ProcessId $_.ProcessId -ServiceName "Backend Worker"
    $beCount++
}
# Close backend console window
Get-Process | Where-Object { $_.MainWindowTitle -match "PREVENT-X Backend API" } | Stop-Process -Force -ErrorAction SilentlyContinue
if ($beCount -gt 0) {
    Record-Status "FastAPI Backend (:8002)" "Terminated $beCount process(es)" "STOPPED" "Green"
} else {
    Record-Status "FastAPI Backend (:8002)" "No active listener detected" "NOT RUNNING" "Gray"
}

# -----------------------------------------------------------------------------
# 3. Stop Upstream Test Application (Port 8086)
# -----------------------------------------------------------------------------
$upPids = Get-NetTCPConnection -LocalPort 8086 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique
$upCount = 0
if ($upPids) {
    foreach ($pidToKill in $upPids) {
        Terminate-ProcessById -ProcessId $pidToKill -ServiceName "Upstream App"
        $upCount++
    }
}
# Also find python process running run_upstream_app.py
Get-CimInstance Win32_Process | Where-Object {
    ($_.CommandLine -match "run_upstream_app") -or
    ($_.CommandLine -match "PREVENT-X" -and $_.CommandLine -match "8086")
} | ForEach-Object {
    Terminate-ProcessById -ProcessId $_.ProcessId -ServiceName "Upstream App"
    $upCount++
}
# Also check pid file
$upPidFile = Join-Path $LogsDir "upstream.pid"
if (Test-Path $upPidFile) {
    try {
        $savedUpPid = (Get-Content $upPidFile -Raw).Trim()
        if ($savedUpPid) {
            Terminate-ProcessById -ProcessId $savedUpPid -ServiceName "Upstream App"
            $upCount++
        }
        Remove-Item $upPidFile -Force -ErrorAction SilentlyContinue
    } catch {}
}
# Close upstream console window
Get-Process | Where-Object { $_.MainWindowTitle -match "PREVENT-X Upstream Test App" } | Stop-Process -Force -ErrorAction SilentlyContinue
if ($upCount -gt 0) {
    Record-Status "Upstream Test App (:8086)" "Terminated $upCount process(es)" "STOPPED" "Green"
} else {
    Record-Status "Upstream Test App (:8086)" "No active listener detected" "NOT RUNNING" "Gray"
}

# -----------------------------------------------------------------------------
# 4. Stop Nginx Virtual Patch Reverse Proxy (Port 8085)
# -----------------------------------------------------------------------------
$nginxDir = Join-Path $Root "infrastructure\bin\nginx"
$nginxExe = Join-Path $nginxDir "nginx.exe"
$nginxStopped = $false
if (Test-Path $nginxExe) {
    try {
        & $nginxExe -p "$nginxDir" -c "conf/preventx_active.conf" -s stop 2>&1 | Out-Null
        Start-Sleep -Seconds 1
        $nginxStopped = $true
    } catch {}
}
# If port 8085 is still listening, stop the specific process
$nginxPids = Get-NetTCPConnection -LocalPort 8085 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique
if ($nginxPids) {
    foreach ($pidToKill in $nginxPids) {
        $proc = Get-Process -Id $pidToKill -ErrorAction SilentlyContinue
        if ($proc -and $proc.Path -match "nginx") {
            Stop-Process -Id $pidToKill -Force -ErrorAction SilentlyContinue
            $nginxStopped = $true
        }
    }
}
# Also clean up any lingering nginx.exe from infrastructure\bin\nginx
Get-Process nginx -ErrorAction SilentlyContinue | Where-Object { $_.Path -match "PREVENT-X" } | Stop-Process -Force -ErrorAction SilentlyContinue

# Clean stale pid file
$nginxPidFile = Join-Path $nginxDir "logs\nginx.pid"
if (Test-Path $nginxPidFile) {
    Remove-Item $nginxPidFile -Force -ErrorAction SilentlyContinue
}
Record-Status "Nginx Virtual Patch Proxy (:8085)" "Gracefully stopped via nginx -s stop" "STOPPED" "Green"

# -----------------------------------------------------------------------------
# 5. Stop Celery Worker
# -----------------------------------------------------------------------------
$celeryCount = 0
Get-CimInstance Win32_Process | Where-Object {
    ($_.CommandLine -match "backend\.app\.workers\.celery_app") -or
    ($_.CommandLine -match "PREVENT-X" -and $_.CommandLine -match "run_worker")
} | ForEach-Object {
    Terminate-ProcessById -ProcessId $_.ProcessId -ServiceName "Celery Worker"
    $celeryCount++
}
# Close celery console window
Get-Process | Where-Object { $_.MainWindowTitle -match "PREVENT-X Celery Worker" } | Stop-Process -Force -ErrorAction SilentlyContinue
if ($celeryCount -gt 0) {
    Record-Status "Celery Background Worker" "Terminated $celeryCount process(es)" "STOPPED" "Green"
} else {
    Record-Status "Celery Background Worker" "No active Celery worker found" "NOT RUNNING" "Gray"
}

# -----------------------------------------------------------------------------
# 6. Close any remaining PREVENT-X launcher windows
# -----------------------------------------------------------------------------
Get-Process | Where-Object { $_.MainWindowTitle -match "^PREVENT-X" } | Stop-Process -Force -ErrorAction SilentlyContinue

# Clean up PID manifest
if (Test-Path $pidsFile) {
    Remove-Item $pidsFile -Force -ErrorAction SilentlyContinue
}

# -----------------------------------------------------------------------------
# 7. PostgreSQL & Redis Persistence Handling
# -----------------------------------------------------------------------------
$pgStatus = "ACTIVE (Preserved)"
$redisStatus = "ACTIVE (Preserved)"
if ($StopAll) {
    Write-Host "[*] User requested complete shutdown of PostgreSQL and Redis..." -ForegroundColor Yellow
    
    # Graceful stop of PostgreSQL using pg_ctl to preserve all data cleanly
    $pgCtl = Join-Path $Root "infrastructure\bin\postgres\bin\pg_ctl.exe"
    $pgData = Join-Path $Root "data\pgdata"
    if (Test-Path $pgCtl) {
        & $pgCtl stop -D "$pgData" -m fast *>$null
    } else {
        Get-Process postgres -ErrorAction SilentlyContinue | Where-Object { $_.Path -match "PREVENT-X" } | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    $pgStatus = "STOPPED (Data Preserved)"

    # Graceful stop of Redis using redis-cli shutdown save
    $redisCli = Join-Path $Root "infrastructure\bin\redis\redis-cli.exe"
    if (Test-Path $redisCli) {
        & $redisCli -p 6379 shutdown save *>$null
    } else {
        Get-Process redis-server -ErrorAction SilentlyContinue | Where-Object { $_.Path -match "PREVENT-X" } | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    $redisStatus = "STOPPED (Data Preserved)"
}

Record-Status "PostgreSQL Database (:54320)" "Data intact in data\pgdata" $pgStatus "Cyan"
Record-Status "Redis Cache & Broker (:6379)" "Data intact in dump.rdb" $redisStatus "Cyan"

# Display Shutdown Table
Write-Host ""
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host "                 PREVENT-X LAB SHUTDOWN REPORT" -ForegroundColor Green
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host ("{0,-38} {1,-26} {2}" -f "Service", "Action", "Status") -ForegroundColor White
Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
foreach ($item in $shutdownReport) {
    $fg = if ($item.Color -eq "Green") { "Green" } elseif ($item.Color -eq "Cyan") { "Cyan" } else { "Gray" }
    Write-Host ("{0,-38} {1,-26} {2}" -f $item.Service, $item.Action, $item.Status) -ForegroundColor $fg
}
Write-Host "------------------------------------------------------------------------------" -ForegroundColor Gray
Write-Host ""
if (-not $StopAll) {
    Write-Host "Notice: PostgreSQL (:54320) and Redis (:6379) remain active for instant next startup." -ForegroundColor Gray
    Write-Host "        All data is safely preserved in data\pgdata and dump.rdb." -ForegroundColor Gray
    Write-Host "        To also stop PostgreSQL and Redis, run: powershell scripts\stop_lab.ps1 -StopAll" -ForegroundColor Gray
}
Write-Host ""
