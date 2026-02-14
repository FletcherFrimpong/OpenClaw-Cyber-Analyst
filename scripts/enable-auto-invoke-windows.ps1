param(
  [string]$TaskName = "OpenClawCyberSecurityEngineerAuto"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Runner = Join-Path $RepoRoot "scripts\auto-invoke-security-cycle.sh"

if (-not (Test-Path $Runner)) {
  throw "Runner script not found: $Runner"
}

$action = New-ScheduledTaskAction -Execute "wsl.exe" -Argument "/bin/bash `"$Runner`""
$trigger1 = New-ScheduledTaskTrigger -AtLogOn
$trigger2 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
  -RepetitionInterval (New-TimeSpan -Minutes 30) `
  -RepetitionDuration ([TimeSpan]::MaxValue)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($trigger1,$trigger2) -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "Auto-invoke enabled via Windows Task Scheduler: $TaskName"
