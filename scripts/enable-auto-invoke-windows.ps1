param(
  [string]$TaskName = "OpenClawCyberSecurityEngineerAuto"
)

# Windows support is through WSL: OpenClaw and this skill run inside your WSL
# distribution, and this task only starts the security cycle there every 30
# minutes. Install the skill inside WSL first (scripts/install-skill.sh).
# This path has not been tested on a real Windows machine.

$ErrorActionPreference = "Stop"

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
  throw "wsl.exe was not found. Install WSL, then install OpenClaw and this skill inside it."
}

# The runner path is resolved by bash inside WSL, so it is the Linux home, not the Windows one.
$Runner = '$HOME/.openclaw/workspace/skills/cyber-security-engineer/scripts/auto_invoke_cycle.sh'
& wsl.exe -- bash -lc "test -x $Runner"
if ($LASTEXITCODE -ne 0) {
  throw "The skill is not installed inside WSL. Run scripts/install-skill.sh from a WSL shell first."
}

$action = New-ScheduledTaskAction -Execute "wsl.exe" -Argument "-- bash -lc `"$Runner`""
$trigger1 = New-ScheduledTaskTrigger -AtLogOn
$trigger2 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
  -RepetitionInterval (New-TimeSpan -Minutes 30) `
  -RepetitionDuration ([TimeSpan]::MaxValue)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($trigger1,$trigger2) -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "Auto-invoke enabled via Windows Task Scheduler (runs inside WSL): $TaskName"
