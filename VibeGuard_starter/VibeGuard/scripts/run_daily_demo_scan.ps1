$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot
$Python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path $Python)) { throw 'VibeGuard virtual environment not found. Run setup first.' }
& $Python main.py scan-repo (Join-Path $ProjectRoot 'demo')
if ($LASTEXITCODE -ne 0) { throw "VibeGuard scan failed with exit code $LASTEXITCODE" }
