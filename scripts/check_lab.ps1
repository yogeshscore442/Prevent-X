# ==============================================================================
# PREVENT-X: Security Testing Lab Health Verification (PowerShell Wrapper)
# ==============================================================================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent $ScriptDir
Set-Location $Root

$pythonExe = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $pythonExe)) {
    Write-Host "[-] Python virtual environment not found at $pythonExe" -ForegroundColor Red
    exit 1
}

& $pythonExe "$Root\scripts\check_lab.py" $args
exit $LASTEXITCODE
