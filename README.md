# OpenClaw-Cyber-Analyst

Security automation skillset for OpenClaw.

This repo ships the `cyber-security-engineer` skill: least-privilege guardrails, approval-first elevation, port + egress monitoring, and ISO 27001 + NIST benchmarking with a local dashboard.

## Core Capabilities

### Least Privilege, Scoped Approvals, Audit Trail

Privileged actions should be executed through:

```bash
python3 cyber-security-engineer/scripts/guarded_privileged_exec.py \
  --reason "why root is needed" \
  --use-sudo \
  -- <command> <args...>
```

This enforces:

- Approval-first privileged execution
- Command allow/deny policy enforcement (when configured)
- Per-task session scoping (optional)
- Automatic drop back to normal after the command (default; `--keep-session` is available)
- Append-only privileged audit log: `~/.openclaw/security/privileged-audit.jsonl`

### Approved Ports Baseline

Port monitoring compares listeners to an approved baseline. Generate one from current services:

```bash
python3 cyber-security-engineer/scripts/generate_approved_ports.py
```

This writes `~/.openclaw/security/approved_ports.json`. Review and prune it for approved services.
A starter template is available at `cyber-security-engineer/references/approved_ports.template.json`.

Port discovery uses `lsof` when available, with fallbacks to `ss` (Linux) or `netstat` (Windows).

### Runtime Enforcement Hook (Optional)

To reduce bypasses (running raw `sudo`), install the runtime hook which places a `sudo` shim at:

`~/.openclaw/bin/sudo`

Install:

```bash
./cyber-security-engineer/scripts/install-openclaw-runtime-hook.sh
openclaw gateway restart
```

Skip hook during bootstrap:

```bash
ENFORCE_PRIVILEGED_EXEC=0 ./scripts/bootstrap-openclaw-cyber-analyst.sh
```

### Egress Monitoring (Outbound Allowlist)

Egress monitoring inventories outbound TCP connections and compares them to:

`~/.openclaw/security/egress_allowlist.json`

Run:

```bash
python3 cyber-security-engineer/scripts/egress_monitor.py --json
```

Template:

`cyber-security-engineer/references/egress-allowlist.template.json`

### Notifications On New Violations (Optional)

The auto-invoke cycle runs `notify_on_violation.py`, which compares the latest compliance summary against the previous run and emits a message when new violations/partials appear.

To wire notifications to your own channel, set a command to run with the message piped on stdin:

```bash
export OPENCLAW_VIOLATION_NOTIFY_CMD="your_notify_command_here"
```

Example (log to system logger):

```bash
export OPENCLAW_VIOLATION_NOTIFY_CMD="logger -t openclaw-cyber-security-engineer"
```

## Compliance Dashboard (ISO 27001 + NIST)

The skill maps observed OpenClaw/host posture to ISO 27001 and NIST categories.

## Preflight & Safety Checks

Requirements:

- Env vars (optional): `OPENCLAW_REQUIRE_POLICY_FILES`, `OPENCLAW_REQUIRE_SESSION_ID`, `OPENCLAW_TASK_SESSION_ID`, `OPENCLAW_APPROVAL_TOKEN`, `OPENCLAW_UNTRUSTED_SOURCE`, `OPENCLAW_VIOLATION_NOTIFY_CMD`
- Tools: `python3` and one of `lsof` / `ss` / `netstat`
- Policy files under `~/.openclaw/security`: `approved_ports.json`, `command-policy.json`, `egress_allowlist.json` (and optionally `prompt-policy.json`)

Before enabling hooks or auto-invoke, run:

```bash
python3 cyber-security-engineer/scripts/preflight_check.py
```

You can enforce policy file presence for privileged execution by setting:

```bash
export OPENCLAW_REQUIRE_POLICY_FILES=1
```

Safety notes:

- Do not run install scripts as root unless you reviewed them. Set `ALLOW_ROOT=1` to override.
- Notifications are opt-in; `notify_on_violation.py` only runs a command if you set `OPENCLAW_VIOLATION_NOTIFY_CMD`.
- Policy files must be reviewed by an administrator before enabling privileged execution.

## Advanced Guardrails (Optional)

### Command Policy (Allow/Deny)

Create `~/.openclaw/security/command-policy.json` using:

`cyber-security-engineer/references/command-policy.template.json`

If `allow` is non-empty, only matching commands are permitted. Any `deny` match blocks execution.

### Prompt-Injection Confirmation

Create `~/.openclaw/security/prompt-policy.json` using:

`cyber-security-engineer/references/prompt-policy.template.json`

When `OPENCLAW_UNTRUSTED_SOURCE=1` is set, privileged actions require explicit confirmation.

### Task Session Boundary Enforcement

To scope approvals to a task:

```bash
export OPENCLAW_REQUIRE_SESSION_ID=1
export OPENCLAW_TASK_SESSION_ID="<task-id>"
```

### Multi-Factor Approval (Token)

Set an approval token in `~/.openclaw/env`:

```bash
export OPENCLAW_APPROVAL_TOKEN="<token>"
```

Privileged approvals will require the token entry.

## Install (New Users)

From repo root:

```bash
chmod +x scripts/bootstrap-openclaw-cyber-analyst.sh
./scripts/bootstrap-openclaw-cyber-analyst.sh
```

Skip scheduler:

```bash
AUTO_INVOKE=0 ./scripts/bootstrap-openclaw-cyber-analyst.sh
```

## Run Manually

```bash
./scripts/auto-invoke-security-cycle.sh
```

Outputs (refreshed each cycle):

- `cyber-security-engineer/assessments/openclaw-assessment.json`
- `cyber-security-engineer/assessments/compliance-summary.json`
- `cyber-security-engineer/assessments/compliance-dashboard.html`
- `cyber-security-engineer/assessments/port-monitor-latest.json`
- `cyber-security-engineer/assessments/egress-monitor-latest.json`

## View Dashboard Locally

```bash
cd cyber-security-engineer/assessments
python3 -m http.server 8088
```

Open:

- `http://127.0.0.1:8088/compliance-dashboard.html`

