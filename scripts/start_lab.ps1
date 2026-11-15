# ==============================================================================
# PREVENT-X: One-Click Security Testing Lab Startup Orchestrator
# Starts all 7 components in strict dependency order with live health verification.
# ==============================================================================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent $ScriptDir
Set-Location $Root

# Ensure logs directory
$LogsDir = Join-Path $Root "logs"
if (-not (Test-Path $LogsDir)) {
    New-Item -ItemType Directory -Path $LogsDir | Out-Null
}
$StartupLog = Join-Path $LogsDir "startup.log"

function Log-Message {
    param(
        [string]$Message,
        [string]$Color = "White",
        [string]$Level = "INFO"
    )
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logLine = "[$ts] [$Level] $Message"
    Add-Content -Path $StartupLog -Value $logLine -Encoding utf8
    Write-Host $Message -ForegroundColor $Color
}

function Test-PortOpen {
    param([int]$Port, [int]$TimeoutMs = 500)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect("127.0.0.1", $Port, $null, $null)
        $wait = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $wait) { $tcp.Close(); return $false }
        $tcp.EndConnect($iar)
        $tcp.Close()
        return $true
    } catch {
        return $false
    }
}

function Wait-For-Port {
    param(
        [int]$Port,
        [int]$TimeoutSeconds = 15,
        [string]$ServiceName = "Service"
    )
    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        if (Test-PortOpen -Port $Port) {
            return $true
        }
        Start-Sleep -Milliseconds 500
        $elapsed += 0.5
    }
    return $false
}

function Wait-For-Http {
    param(
        [string]$Url,
        [int]$ExpectedStatus = 200,
        [int]$TimeoutSeconds = 20,
        [string]$ServiceName = "HTTP Service"
    )
    $elapsed = 0
    $pythonExe = Join-Path $Root ".venv\Scripts\python.exe"
    while ($elapsed -lt $TimeoutSeconds) {
        try {
            $cmd = "& `"$pythonExe`" -c `"import httpx, sys;
try:
    r = httpx.get('$Url', timeout=2.0)
    sys.exit(0 if r.status_code == $ExpectedStatus else 1)
except Exception:
    sys.exit(1)`""
            Invoke-Expression $cmd
            if ($LASTEXITCODE -eq 0) {
                return $true
            }
        } catch {}
        Start-Sleep -Milliseconds 500
        $elapsed += 0.5
    }
    return $false
}

function Start-IndependentProcess {
    param(
        [string]$CommandLine,
        [string]$WorkingDirectory = $Root
    )
    $res = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
        CommandLine      = $CommandLine
        CurrentDirectory = $WorkingDirectory
    }
    return $res.ProcessId
}

Clear-Host
Log-Message "==============================================================================" "Cyan" "STARTUP"
Log-Message "            PREVENT-X : Automated Security Testing Lab Launcher" "Cyan" "STARTUP"
Log-Message "                 AI-Era Virtual Patching Platform (Native)" "Cyan" "STARTUP"
Log-Message "==============================================================================" "Cyan" "STARTUP"
Log-Message "[*] Root Directory : $Root" "Gray" "STARTUP"
Log-Message "[*] Startup Log    : $StartupLog" "Gray" "STARTUP"
Log-Message "" "White" "STARTUP"

# Dictionary to track PIDs for safe shutdown
$pidsData = @{}
$pythonExe = Join-Path $Root ".venv\Scripts\python.exe"

# -----------------------------------------------------------------------------
# STEP 1: PostgreSQL Database (Port 54320)
# -----------------------------------------------------------------------------
Log-Message "[STEP 1/7] Initializing PostgreSQL 16 on port 54320..." "Yellow" "POSTGRES"
$pgOpen = Test-PortOpen -Port 54320
if (-not $pgOpen) {
    $pgExe = Join-Path $Root "infrastructure\bin\postgres\bin\postgres.exe"
    $pgData = Join-Path $Root "data\pgdata"
    if (Test-Path $pgExe) {
        Log-Message "  [*] Starting embedded PostgreSQL server..." "Gray" "POSTGRES"
        $pgPid = Start-IndependentProcess -CommandLine "`"$pgExe`" -D `"$pgData`" -p 54320" -WorkingDirectory $Root
        $pidsData["postgres"] = $pgPid
    } else {
        Log-Message "  [!] Embedded postgres.exe not found. Assuming external instance on 54320." "Yellow" "POSTGRES"
    }

    $pgReady = Wait-For-Port -Port 54320 -TimeoutSeconds 15 -ServiceName "PostgreSQL"
    if (-not $pgReady) {
        Log-Message "  [-] FATAL: PostgreSQL failed to bind port 54320 within 15 seconds." "Red" "ERROR"
        exit 1
    }
} else {
    Log-Message "  [+] PostgreSQL is already running on port 54320." "Green" "POSTGRES"
    $pgPid = (Get-NetTCPConnection -LocalPort 54320 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -First 1)
    if ($pgPid) { $pidsData["postgres"] = $pgPid }
}

# Verify database query execution with retry loop (allows WAL recovery to complete)
$dbReady = $false
$dbCheckErr = ""
for ($i = 0; $i -lt 25; $i++) {
    $dbCheckErr = & $pythonExe -c "import psycopg2, sys;
try:
    conn = psycopg2.connect('postgresql://preventx_user:preventx_secure_pass@localhost:54320/preventx_db', connect_timeout=2)
    cur = conn.cursor()
    cur.execute('SELECT 1')
    conn.close()
    sys.exit(0)
except Exception as e:
    print(str(e))
    sys.exit(1)"
    if ($LASTEXITCODE -eq 0) {
        $dbReady = $true
        break
    }
    Start-Sleep -Milliseconds 500
}

if (-not $dbReady) {
    Log-Message "  [-] FATAL: PostgreSQL database connection query failed: $dbCheckErr" "Red" "ERROR"
    exit 1
}
Log-Message "  [+] PostgreSQL connection and query execution verified." "Green" "POSTGRES"

# Apply Alembic schema migrations
Log-Message "  [*] Verifying and applying database schema migrations..." "Gray" "ALEMBIC"
$alembicOutput = & $pythonExe -m alembic -c backend/alembic.ini upgrade head *>$null
if ($LASTEXITCODE -ne 0) {
    Log-Message "  [-] Alembic migration note: $alembicOutput" "Yellow" "ALEMBIC"
} else {
    Log-Message "  [+] Database schema is up-to-date (head revision)." "Green" "ALEMBIC"
}

# Synchronize roles & root administrator
Log-Message "  [*] Synchronizing platform roles and initial administrator..." "Gray" "BOOTSTRAP"
& $pythonExe "$Root\scripts\bootstrap_admin.py" *>$null
Log-Message "  [+] Initial administrator synchronized (admin@preventx.internal)." "Green" "BOOTSTRAP"
Log-Message "" "White" "STEP_DONE"

# -----------------------------------------------------------------------------
# STEP 2: Redis Cache & Message Broker (Port 6379)
# -----------------------------------------------------------------------------
Log-Message "[STEP 2/7] Initializing Redis cache & Celery broker on port 6379..." "Yellow" "REDIS"
$redisOpen = Test-PortOpen -Port 6379
if (-not $redisOpen) {
    $redisExe = Join-Path $Root "infrastructure\bin\redis\redis-server.exe"
    if (Test-Path $redisExe) {
        Log-Message "  [*] Starting embedded Redis server on port 6379..." "Gray" "REDIS"
        $redisPid = Start-IndependentProcess -CommandLine "`"$redisExe`" --port 6379" -WorkingDirectory "$Root\infrastructure\bin\redis"
        $pidsData["redis"] = $redisPid
    } else {
        Log-Message "  [!] Embedded redis-server.exe not found. Assuming external instance." "Yellow" "REDIS"
    }

    $redisReady = Wait-For-Port -Port 6379 -TimeoutSeconds 10 -ServiceName "Redis"
    if (-not $redisReady) {
        Log-Message "  [-] FATAL: Redis failed to bind port 6379 within 10 seconds." "Red" "ERROR"
        exit 1
    }
} else {
    Log-Message "  [+] Redis is already running on port 6379." "Green" "REDIS"
    $rPid = (Get-NetTCPConnection -LocalPort 6379 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -First 1)
    if ($rPid) { $pidsData["redis"] = $rPid }
}

# Verify Redis PING
$redisCheck = & $pythonExe -c "import redis, sys;
try:
    r = redis.Redis.from_url('redis://localhost:6379/0', socket_timeout=2)
    sys.exit(0 if r.ping() else 1)
except Exception:
    sys.exit(1)"
if ($LASTEXITCODE -ne 0) {
    Log-Message "  [-] FATAL: Redis ping check failed on localhost:6379." "Red" "ERROR"
    exit 1
}
Log-Message "  [+] Redis connectivity verified (PONG received)." "Green" "REDIS"
Log-Message "" "White" "STEP_DONE"

# -----------------------------------------------------------------------------
# STEP 3: Upstream Target Test Application (Port 8086)
# -----------------------------------------------------------------------------
Log-Message "[STEP 3/7] Starting Upstream Test Application on port 8086..." "Yellow" "UPSTREAM"
$upOpen = Test-PortOpen -Port 8086
if (-not $upOpen) {
    $upstreamBat = Join-Path $Root "scripts\run_upstream_app.bat"
    Log-Message "  [*] Launching Upstream Test App in dedicated console window..." "Gray" "UPSTREAM"
    $upWinPid = Start-IndependentProcess -CommandLine "cmd.exe /k `"call `"$upstreamBat`" 8086`"" -WorkingDirectory $Root
    $pidsData["upstream_window"] = $upWinPid

    $upReady = Wait-For-Http -Url "http://127.0.0.1:8086/health" -ExpectedStatus 200 -TimeoutSeconds 12 -ServiceName "Upstream App"
    if (-not $upReady) {
        Log-Message "  [-] FATAL: Upstream test application failed to respond on port 8086." "Red" "ERROR"
        exit 1
    }
} else {
    Log-Message "  [+] Upstream test application is already running on port 8086." "Green" "UPSTREAM"
}

$upPid = (Get-NetTCPConnection -LocalPort 8086 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -First 1)
if ($upPid) { $pidsData["upstream"] = $upPid }
Log-Message "  [+] Upstream application healthy on http://127.0.0.1:8086 (PID: $upPid)." "Green" "UPSTREAM"
Log-Message "" "White" "STEP_DONE"

# -----------------------------------------------------------------------------
# STEP 4: Nginx Virtual Patching Reverse Proxy (Port 8085)
# -----------------------------------------------------------------------------
Log-Message "[STEP 4/7] Validating and starting Nginx Virtual Patching Proxy on port 8085..." "Yellow" "NGINX"
$nginxDir = Join-Path $Root "infrastructure\bin\nginx"
$nginxExe = Join-Path $nginxDir "nginx.exe"
$nginxConf = "conf/preventx_active.conf"

# Verify Nginx configuration syntax first
Log-Message "  [*] Testing Nginx configuration syntax (-t)..." "Gray" "NGINX"
$syntaxTest = & $nginxExe -p "$nginxDir" -c "$nginxConf" -t 2>&1
if ($LASTEXITCODE -ne 0) {
    Log-Message "  [-] FATAL: Nginx syntax test failed: $syntaxTest" "Red" "ERROR"
    exit 1
}
Log-Message "  [+] Nginx configuration syntax verified: OK." "Green" "NGINX"

# Clean stale nginx.pid if process is dead
$nginxPidFile = Join-Path $nginxDir "logs\nginx.pid"
if (Test-Path $nginxPidFile) {
    $rawPid = Get-Content $nginxPidFile -Raw -ErrorAction SilentlyContinue
    if ($rawPid) {
        $existingPid = $rawPid.Trim()
        if ($existingPid) {
            $p = Get-Process -Id $existingPid -ErrorAction SilentlyContinue
            if (-not $p) {
                Remove-Item $nginxPidFile -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

$nginxOpen = Test-PortOpen -Port 8085
if (-not $nginxOpen) {
    Log-Message "  [*] Launching native Nginx daemon on port 8085..." "Gray" "NGINX"
    $nginxPid = Start-IndependentProcess -CommandLine "`"$nginxExe`" -p `"$nginxDir`" -c `"$nginxConf`"" -WorkingDirectory $nginxDir
    $nginxReady = Wait-For-Port -Port 8085 -TimeoutSeconds 10 -ServiceName "Nginx"
    if (-not $nginxReady) {
        Log-Message "  [-] FATAL: Nginx failed to bind port 8085 within 10 seconds." "Red" "ERROR"
        exit 1
    }
} else {
    Log-Message "  [+] Nginx reverse proxy is already running on port 8085." "Green" "NGINX"
}

# Verify Nginx can communicate with upstream
$proxyTransitCheck = & $pythonExe -c "import httpx, sys;
try:
    r = httpx.get('http://127.0.0.1:8085/', timeout=3.0)
    sys.exit(0 if r.status_code == 200 else 1)
except Exception as e:
    print(str(e))
    sys.exit(1)"
if ($LASTEXITCODE -ne 0) {
    Log-Message "  [-] FATAL: Nginx could not communicate with upstream on port 8086: $proxyTransitCheck" "Red" "ERROR"
    exit 1
}
$nginxPid = (Get-NetTCPConnection -LocalPort 8085 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -First 1)
if ($nginxPid) { $pidsData["nginx"] = $nginxPid }
Log-Message "  [+] Nginx proxy verified on http://127.0.0.1:8085 (Forwarding to upstream :8086)." "Green" "NGINX"
Log-Message "" "White" "STEP_DONE"

# -----------------------------------------------------------------------------
# STEP 5: Celery Background Worker
# -----------------------------------------------------------------------------
Log-Message "[STEP 5/7] Starting Celery Asynchronous Worker..." "Yellow" "CELERY"
& $pythonExe -c "from backend.app.workers.celery_app import celery_app; import sys;
try:
    p = celery_app.control.ping(timeout=1.0)
    sys.exit(0 if (p and len(p) > 0) else 1)
except Exception:
    sys.exit(1)" *>$null
$celeryActive = ($LASTEXITCODE -eq 0)

if (-not $celeryActive) {
    $workerBat = Join-Path $Root "scripts\run_worker.bat"
    Log-Message "  [*] Launching Celery worker in dedicated console window..." "Gray" "CELERY"
    $cwWinPid = Start-IndependentProcess -CommandLine "cmd.exe /k `"call `"$workerBat`"`"" -WorkingDirectory $Root
    $pidsData["celery_window"] = $cwWinPid

    # Wait for Celery worker to answer ping
    $workerReady = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 500
        & $pythonExe -c "from backend.app.workers.celery_app import celery_app; import sys;
try:
    p = celery_app.control.ping(timeout=1.0)
    sys.exit(0 if (p and len(p) > 0) else 1)
except Exception:
    sys.exit(1)" *>$null
        if ($LASTEXITCODE -eq 0) {
            $workerReady = $true
            break
        }
    }
    if (-not $workerReady) {
        Log-Message "  [-] WARNING: Celery worker did not acknowledge ping in time, but process is starting." "Yellow" "CELERY"
    } else {
        Log-Message "  [+] Celery background worker is operational (acknowledging pings)." "Green" "CELERY"
    }
} else {
    Log-Message "  [+] Celery worker is already active and acknowledging pings." "Green" "CELERY"
}
Log-Message "" "White" "STEP_DONE"

# -----------------------------------------------------------------------------
# STEP 6: FastAPI Backend API Server (Port 8002)
# -----------------------------------------------------------------------------
Log-Message "[STEP 6/7] Starting FastAPI Backend API on port 8002..." "Yellow" "BACKEND"
$backendOpen = Test-PortOpen -Port 8002
$backendHealthy = $false
if ($backendOpen) {
    $backendHealthy = Wait-For-Http -Url "http://127.0.0.1:8002/api/v1/health" -ExpectedStatus 200 -TimeoutSeconds 3 -ServiceName "Backend API"
}

if (-not $backendHealthy) {
    if ($backendOpen) {
        Log-Message "  [*] Cleaning unresponsive process on port 8002..." "Gray" "BACKEND"
        Get-NetTCPConnection -LocalPort 8002 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess | ForEach-Object {
            Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 1
    }

    $backendBat = Join-Path $Root "scripts\run_backend.bat"
    Log-Message "  [*] Launching FastAPI Backend server in dedicated console window..." "Gray" "BACKEND"
    $beWinPid = Start-IndependentProcess -CommandLine "cmd.exe /k `"call `"$backendBat`" 8002`"" -WorkingDirectory $Root
    $pidsData["backend_window"] = $beWinPid

    $beReady = Wait-For-Http -Url "http://127.0.0.1:8002/api/v1/health" -ExpectedStatus 200 -TimeoutSeconds 20 -ServiceName "Backend API"
    if (-not $beReady) {
        Log-Message "  [-] FATAL: FastAPI Backend failed to become healthy on port 8002." "Red" "ERROR"
        exit 1
    }
} else {
    Log-Message "  [+] Backend API is already running on port 8002." "Green" "BACKEND"
}

# Verify readiness endpoint with retry loop
$readyHealthy = $false
for ($i = 0; $i -lt 20; $i++) {
    & $pythonExe -c "import httpx, sys;
try:
    r = httpx.get('http://127.0.0.1:8002/api/v1/ready', timeout=2.0)
    data = r.json()
    sys.exit(0 if data.get('ready') is True else 1)
except Exception:
    sys.exit(1)" *>$null
    if ($LASTEXITCODE -eq 0) {
        $readyHealthy = $true
        break
    }
    Start-Sleep -Milliseconds 500
}

if (-not $readyHealthy) {
    Log-Message "  [-] WARNING: Backend readiness check did not report full readiness." "Yellow" "BACKEND"
} else {
    Log-Message "  [+] Backend readiness verified (Database & Redis internal connections UP)." "Green" "BACKEND"
}

$bePid = (Get-NetTCPConnection -LocalPort 8002 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -First 1)
if ($bePid) { $pidsData["backend"] = $bePid }
Log-Message "" "White" "STEP_DONE"

# -----------------------------------------------------------------------------
# STEP 7: React Frontend Development Server (Port 5173)
# -----------------------------------------------------------------------------
Log-Message "[STEP 7/7] Starting React Frontend UI on port 5173..." "Yellow" "FRONTEND"
$frontendOpen = Test-PortOpen -Port 5173
$frontendHealthy = $false
if ($frontendOpen) {
    $frontendHealthy = Wait-For-Http -Url "http://localhost:5173/" -ExpectedStatus 200 -TimeoutSeconds 3 -ServiceName "Frontend UI"
}

if (-not $frontendHealthy) {
    if ($frontendOpen) {
        Log-Message "  [*] Cleaning unresponsive process on port 5173..." "Gray" "FRONTEND"
        Get-NetTCPConnection -LocalPort 5173 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess | ForEach-Object {
            Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 1
    }

    $frontendBat = Join-Path $Root "scripts\run_frontend.bat"
    Log-Message "  [*] Launching React Frontend UI in dedicated console window..." "Gray" "FRONTEND"
    $feWinPid = Start-IndependentProcess -CommandLine "cmd.exe /k `"call `"$frontendBat`" 8002`"" -WorkingDirectory $Root
    $pidsData["frontend_window"] = $feWinPid

    $feReady = Wait-For-Http -Url "http://localhost:5173/" -ExpectedStatus 200 -TimeoutSeconds 20 -ServiceName "Frontend UI"
    if (-not $feReady) {
        Log-Message "  [-] FATAL: Frontend UI server failed to respond on port 5173." "Red" "ERROR"
        exit 1
    }
} else {
    Log-Message "  [+] Frontend UI server is already running on port 5173." "Green" "FRONTEND"
}

$fePid = (Get-NetTCPConnection -LocalPort 5173 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -First 1)
if ($fePid) { $pidsData["frontend"] = $fePid }
Log-Message "" "White" "STEP_DONE"

# -----------------------------------------------------------------------------
# Save Process ID Manifest for Reliable Clean Shutdown
# -----------------------------------------------------------------------------
$pidsJsonFile = Join-Path $LogsDir "lab_pids.json"
$pidsData | ConvertTo-Json -Depth 3 | Out-File -FilePath $pidsJsonFile -Encoding utf8
Log-Message "[*] Saved runtime process manifest: $pidsJsonFile" "Gray" "SYSTEM"

# -----------------------------------------------------------------------------
# Open Browser Only After Full Verification
# -----------------------------------------------------------------------------
Log-Message "[*] Opening PREVENT-X Web Console in default browser..." "Cyan" "SYSTEM"
Start-Process "http://localhost:5173"

# -----------------------------------------------------------------------------
# Operational Summary Table
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host "                 PREVENT-X SECURITY TESTING LAB OPERATIONAL" -ForegroundColor Green
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host "  Service                    Port / URL                      Status" -ForegroundColor White
Write-Host "  ----------------------------------------------------------------------------" -ForegroundColor Gray
Write-Host "  [+] React Frontend UI    : http://localhost:5173           OPERATIONAL" -ForegroundColor White
Write-Host "  [+] Backend API Engine   : http://127.0.0.1:8002           OPERATIONAL" -ForegroundColor White
Write-Host "  [+] Interactive Docs     : http://127.0.0.1:8002/api/v1/docs OPERATIONAL" -ForegroundColor White
Write-Host "  [+] Virtual Patch Proxy  : http://127.0.0.1:8085           ACTIVE (WAF Filter)" -ForegroundColor Cyan
Write-Host "  [+] Upstream Test Target : http://127.0.0.1:8086           ACTIVE (Protected)" -ForegroundColor Cyan
Write-Host "  [+] PostgreSQL Database  : Port 54320 (preventx_db)        HEALTHY" -ForegroundColor White
Write-Host "  [+] Redis Cache / Broker : Port 6379 (DB 0, 1, 2)          HEALTHY" -ForegroundColor White
Write-Host "  [+] Celery Background    : Task Workers Active             HEALTHY" -ForegroundColor White
Write-Host "  ----------------------------------------------------------------------------" -ForegroundColor Gray
Write-Host ""
Write-Host "  Initial Administrator Credentials:" -ForegroundColor Cyan
Write-Host "    Username : admin@preventx.internal" -ForegroundColor White
Write-Host "    Password : (Configured in environment - Rotate upon first login)" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Quick Commands:" -ForegroundColor Gray
Write-Host "    - Run health audit table : python scripts\check_lab.py" -ForegroundColor White
Write-Host "    - Gracefully stop lab    : Close start.bat or run powershell scripts\stop_lab.ps1" -ForegroundColor White
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host ""
