# OpenClaw Cyber Analyst

This project adds a security layer to OpenClaw.

In plain terms, it helps you:

- Ask for approval before risky system-level actions
- Track open ports and outbound network connections
- Generate a simple security report you can review in a browser

## Who This Is For

- Non-technical users who want safer defaults
- Technical users who want stronger control and auditability

## 5-Minute Start (Non-Technical)

Run these commands from the project folder:

```bash
chmod +x scripts/bootstrap-openclaw-cyber-analyst.sh
./scripts/bootstrap-openclaw-cyber-analyst.sh
./scripts/auto-invoke-security-cycle.sh
```

Then open the dashboard:

```bash
cd cyber-security-engineer/assessments
python3 -m http.server 8088
```

Open this URL in your browser:

- `http://127.0.0.1:8088/compliance-dashboard.html`

## What You Will See

After each security cycle, these files are updated:

- `cyber-security-engineer/assessments/compliance-dashboard.html`
  - Human-friendly report page
- `cyber-security-engineer/assessments/compliance-summary.json`
  - Structured summary for tools/integrations
- `cyber-security-engineer/assessments/openclaw-assessment.json`
  - Control checklist and status
- `cyber-security-engineer/assessments/port-monitor-latest.json`
  - Latest open-port scan
- `cyber-security-engineer/assessments/egress-monitor-latest.json`
  - Latest outbound connection scan

## Core Protections

### 1) Approval Before Privileged Actions

Privileged commands should be run through:

```bash
python3 cyber-security-engineer/scripts/guarded_privileged_exec.py \
  --reason "why privileged access is needed" \
  --use-sudo \
  -- /absolute/path/to/command arg1 arg2
```

This provides:

- Approval-first execution
- Command policy checks (if configured)
- Automatic drop back to normal mode by default
- Audit logging to `~/.openclaw/security/privileged-audit.jsonl`

### 2) Open Port Monitoring

Generate an approved baseline from current listeners:

```bash
python3 cyber-security-engineer/scripts/generate_approved_ports.py
```

This creates:

- `~/.openclaw/security/approved_ports.json`

Starter template:

- `cyber-security-engineer/references/approved_ports.template.json`

### 3) Outbound Network Monitoring

Check current outbound TCP connections against your allowlist:

```bash
python3 cyber-security-engineer/scripts/egress_monitor.py --json
```

Allowlist path:

- `~/.openclaw/security/egress_allowlist.json`

Starter template:

- `cyber-security-engineer/references/egress-allowlist.template.json`

## Optional Features

### Runtime Hook for `sudo` (opt-in)

This installs a guarded `sudo` shim that requires approval before privileged commands run.
It is **not installed by default**. To enable it during bootstrap:

```bash
ENFORCE_PRIVILEGED_EXEC=1 ./scripts/bootstrap-openclaw-cyber-analyst.sh
```

Or install it standalone:

```bash
./cyber-security-engineer/scripts/install-openclaw-runtime-hook.sh
openclaw gateway restart
```

The shim can be removed at any time by deleting `~/.openclaw/bin/sudo`.

### Notification on New Findings

You can send alerts when new violations/partials appear:

- `OPENCLAW_VIOLATION_NOTIFY_CMD`
  - Command that receives the message on stdin
- `OPENCLAW_VIOLATION_NOTIFY_ALLOWLIST`
  - Allowed notifier commands
  - Supports exact JSON argv rules (recommended) or legacy comma-separated binaries

## Common Terms

- Privileged command
  - A command that needs elevated system permissions
- Baseline
  - The approved list of expected behavior (for example approved ports)
- Egress
  - Outbound network traffic from your machine
- Compliance dashboard
  - A report view mapped to ISO 27001 and NIST checks
