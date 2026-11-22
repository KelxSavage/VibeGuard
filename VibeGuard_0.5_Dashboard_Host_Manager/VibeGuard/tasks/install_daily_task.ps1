param([Parameter(Mandatory=$true)][string]$ProjectPath,[string]$TaskName="VibeGuard-Daily-Repository-Scan",[string]$Time="09:00")
$ErrorActionPreference="Stop"
$Root=(Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Runner=Join-Path $Root "tasks\run_daily_scan.ps1"
$Project=(Resolve-Path $ProjectPath).Path
$Action=New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$Runner`" -ProjectPath `"$Project`""
$Trigger=New-ScheduledTaskTrigger -Daily -At $Time
$Settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Description "Daily local VibeGuard scan of an explicitly selected project folder." -Force | Out-Null
Write-Host "Created daily task '$TaskName' at $Time. Scanning: $Project"
Write-Host "Remove with: Unregister-ScheduledTask -TaskName '$TaskName' -Confirm"
