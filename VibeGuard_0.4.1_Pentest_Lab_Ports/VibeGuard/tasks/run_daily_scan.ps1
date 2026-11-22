param([Parameter(Mandatory=$true)][string]$ProjectPath)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) { $Python = (Get-Command python -ErrorAction Stop).Source }
if (-not (Test-Path $ProjectPath)) { throw "Project path not found: $ProjectPath" }
Push-Location $Root
try { & $Python (Join-Path $Root "main.py") scan-repo (Resolve-Path $ProjectPath).Path }
finally { Pop-Location }
