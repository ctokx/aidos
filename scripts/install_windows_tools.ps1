$ErrorActionPreference = "Stop"

Write-Host "Installing AIDOS Windows toolchain via Scoop..."
Write-Host "This installs what is currently available in Scoop main bucket."

powershell -ExecutionPolicy Bypass -Command "scoop install nmap nuclei ffuf vegeta k6 bombardier"
if ($LASTEXITCODE -ne 0) {
    throw "Scoop install failed with exit code $LASTEXITCODE"
}

Write-Host "Installing sslyze via pip..."
python -m pip install sslyze
if ($LASTEXITCODE -ne 0) {
    throw "pip install sslyze failed with exit code $LASTEXITCODE"
}

$scoopShims = Join-Path $HOME "scoop\shims"
if (Test-Path $scoopShims) {
    $env:PATH = "$scoopShims;$env:PATH"
}

Write-Host ""
Write-Host "Tool detection after install:"
python -c "import asyncio; from aidos.tools import detect_installed_tools; r = asyncio.run(detect_installed_tools()); print('Detected (%s): %s' % (r['total_available'], ', '.join(r['installed']))); print('Missing (%s): %s' % (len(r['missing']), ', '.join(r['missing'])))"

Write-Host ""
Write-Host "Note: For full Nmap capability, install Npcap manually:"
$npcapPath = Join-Path $HOME "scoop\apps\nmap\current\npcap.exe"
Write-Host $npcapPath
