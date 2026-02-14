param(
  [string]$TaskName = "OpenClawCyberSecurityEngineerAuto"
)

$ErrorActionPreference = "Stop"

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
  Write-Host "Auto-invoke disabled: $TaskName"
} else {
  Write-Host "Task not found: $TaskName"
}
