$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Runner = Join-Path $PSScriptRoot 'run_daily_demo_scan.ps1'
$Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$Runner`""
$Trigger = New-ScheduledTaskTrigger -Daily -At 9:00AM
$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
Register-ScheduledTask -TaskName 'VibeGuard Daily Demo Scan' -Action $Action -Trigger $Trigger -Settings $Settings -Description 'Daily local VibeGuard scan of the deliberately vulnerable demo only.' -Force | Out-Null
Write-Host 'Installed: VibeGuard Daily Demo Scan at 9:00 AM.'
Write-Host 'To inspect: Get-ScheduledTask -TaskName "VibeGuard Daily Demo Scan"'
Write-Host 'To remove:  Unregister-ScheduledTask -TaskName "VibeGuard Daily Demo Scan" -Confirm:$false'
