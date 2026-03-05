param(
    [int]$MaxTurns = 20,
    [string]$Model = "gemini-2.5-flash"
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

$scoopShims = Join-Path $HOME "scoop\shims"
if (Test-Path $scoopShims) {
    $env:PATH = "$scoopShims;$env:PATH"
}

if (-not (Test-Path ".env")) {
    throw ".env file not found. Set GEMINI_API_KEY in .env first."
}

$envLine = Get-Content ".env" | Where-Object { $_ -match '^GEMINI_API_KEY=' } | Select-Object -First 1
if (-not $envLine) {
    throw "GEMINI_API_KEY not found in .env"
}

$env:GEMINI_API_KEY = ($envLine -replace '^GEMINI_API_KEY=', '').Trim('"')
$env:PYTHONUTF8 = "1"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 > $null

$labHost = "127.0.0.1"
$labPort = 8081
$target = "http://$labHost`:$labPort"
$traceFile = "aidos_trace_legal_$(Get-Date -Format 'yyyyMMdd_HHmmss').jsonl"

Write-Host "[1/4] Starting legal local lab target at $target ..."
$labProcess = Start-Process -FilePath "python" -ArgumentList "scripts/lab_target.py" -PassThru -WindowStyle Hidden

try {
    Start-Sleep -Seconds 2

    Write-Host "[2/4] Verifying lab availability ..."
    try {
        $health = Invoke-WebRequest -UseBasicParsing -Uri "$target/" -TimeoutSec 5
        if ($health.StatusCode -lt 200 -or $health.StatusCode -ge 500) {
            throw "Lab returned unexpected status code: $($health.StatusCode)"
        }
    }
    catch {
        throw "Lab target failed to start or is unreachable: $($_.Exception.Message)"
    }

    Write-Host "[3/4] Checking available tools ..."
    python -c "import asyncio; from aidos.tools import detect_installed_tools; r = asyncio.run(detect_installed_tools()); print('Detected tools (%s): %s' % (r['total_available'], ', '.join(r['installed']))); print('Missing tools (%s): %s' % (len(r['missing']), ', '.join(r['missing'])))"

    Write-Host "[4/4] Running AIDOS assessment (max-turns=$MaxTurns, model=$Model) ..."
    python -m aidos $target -y --max-turns $MaxTurns --model $Model --trace-file $traceFile
    if ($LASTEXITCODE -ne 0) {
        throw "AIDOS command failed with exit code $LASTEXITCODE"
    }
    Write-Host "Assessment completed."
    Write-Host "Trace file: $traceFile"
}
finally {
    if ($labProcess -and -not $labProcess.HasExited) {
        Stop-Process -Id $labProcess.Id -Force
        Write-Host "Lab process stopped."
    }
}
