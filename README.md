# OpenClaw-Cyber-Analyst

Security automation skillset for OpenClaw.

This repo ships the `cyber-security-engineer` skill: least-privilege guardrails, port and egress monitoring, and ISO 27001 + NIST benchmarking with a local dashboard.

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
- Per-task scoping (optional): approvals can be scoped to a task session id
- Automatic drop back to normal after the command (default; `--keep-session` is available)
- Append-only privileged audit log: `~/.openclaw/security/privileged-audit.jsonl`

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

### Listening Port Monitoring + Approved Baseline

Port monitoring inventories listening TCP ports and flags:

- Unapproved listeners (not in baseline)
- Insecure ports (with safer recommendations)
- Public binds (`0.0.0.0`, `::`, `*`)

Approved baseline file:

`~/.openclaw/security/approved_ports.json`

Generate a baseline from current listeners:

```bash
python3 cyber-security-engineer/scripts/generate_approved_ports.py
```

Template:

`cyber-security-engineer/references/approved_ports.template.json`

### Egress Monitoring (Outbound Allowlist)

Egress monitoring inventories outbound TCP connections and compares them to:

`~/.openclaw/security/egress_allowlist.json`

Run:

```bash
python3 cyber-security-engineer/scripts/egress_monitor.py --json
```

Template:

`cyber-security-engineer/references/egress-allowlist.template.json`

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

## Notifications On New Violations (Optional)

If you want to be alerted when *new* violations/partials appear between security cycles, set:

```bash
export OPENCLAW_VIOLATION_NOTIFY_CMD="<command>"
```

OpenClaw will execute this command and pipe a notification message to its stdin.

Example (log to system logger):

```bash
export OPENCLAW_VIOLATION_NOTIFY_CMD="logger -t openclaw-cyber-security-engineer"
```

## Compliance Dashboard (ISO 27001 + NIST)

The skill maps observed OpenClaw/host posture to ISO 27001 and NIST categories, including checks for:

- Channel allowlists + group mention requirements
- Gateway loopback + token auth validation
- Secrets/config permission hardening
- Privileged audit logging presence
- Backup/recovery presence
- Update hygiene (captures `openclaw --version`)
- Prompt-injection controls, command policy, session boundaries, MFA approvals
- Egress allowlist + unapproved outbound connections

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
