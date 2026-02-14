---
name: cyber-security-engineer
description: Security engineering workflow for OpenClaw privilege governance and hardening. Use when implementing or auditing least-privilege execution, approval-first elevated access, automatic privilege drop after privileged tasks, idle timeout controls for elevated/root sessions, monitoring listening ports, and producing ISO 27001/NIST-aligned compliance findings with mitigations.
---

# Cyber Security Engineer

Implement these controls in every security-sensitive task:

1. Keep default execution in normal (non-root) mode.
2. Request explicit user approval before any elevated command.
3. Scope elevation to the minimum command set required for the active task.
4. Drop elevated state immediately after the privileged command completes.
5. Expire elevated state after 30 idle minutes and require re-approval.
6. Monitor listening network ports and flag insecure or unapproved exposure.
7. If no approved ports baseline exists, generate one and require user review/pruning.
8. Benchmark controls against ISO 27001 and NIST and report violations with mitigations.

## Non-Goals (Web Browsing)

- Do not use web browsing / web search as part of this skill. Keep assessments and recommendations based on local host/OpenClaw state and the bundled references in this skill.

## Files To Use

- `references/least-privilege-policy.md`: Operational policy and acceptance checks.
- `references/port-monitoring-policy.md`: Network port monitoring policy and remediation guidance.
- `references/compliance-controls-map.json`: ISO 27001 and NIST control mapping catalog.
- `references/approved_ports.template.json`: Starter baseline template.
- `scripts/root_session_guard.py`: Stateful idle-timeout and elevation-session helper.
- `scripts/audit_logger.py`: Append-only privileged action audit log writer.
- `scripts/guarded_privileged_exec.py`: Approval-first privileged execution wrapper with per-task allowlist.
- `scripts/install-openclaw-runtime-hook.sh`: Optional runtime `sudo` shim installer.
- `scripts/port_monitor.py`: Listening-port inventory, insecure-port detection, and recommendations.
- `scripts/generate_approved_ports.py`: Create an approved listening-port baseline from current services.
- `scripts/compliance_dashboard.py`: Assessment scaffold and dashboard renderer for controls map, violations, risk, and mitigations.
- `scripts/live_assessment.py`: Populate assessment findings from current machine/OpenClaw runtime state.

## Workflow

1. Validate current policy against `references/least-privilege-policy.md`.
2. For privileged work, use:
   - `python3 scripts/guarded_privileged_exec.py --reason "why root is needed" --use-sudo -- <command> <args...>`
3. If the wrapper requests approval, stop and ask the user for approval.
4. Keep privileged scope per-task and drop immediately after the privileged command finishes (default behavior).
5. Run network exposure monitoring:
   - `python3 scripts/port_monitor.py --json`
6. If no approved baseline exists, generate one:
   - `python3 scripts/generate_approved_ports.py`
7. Initialize/update compliance assessment and render dashboard:
   - `python3 scripts/compliance_dashboard.py init-assessment --system "OpenClaw"`
   - `python3 scripts/live_assessment.py`
   - `python3 scripts/compliance_dashboard.py render`

## Output Contract

When reporting status to the user, include:

1. Current privilege state (`normal` or `elevated`).
2. Whether approval is currently required (and for which command argv).
3. Port-monitoring summary (listening services, unapproved ports, insecure ports, recommendations).
4. Compliance dashboard summary (coverage, violations/partials, risks, and mitigations).

