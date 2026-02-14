---
name: cyber-security-engineer
description: Security engineering workflow for OpenClaw privilege governance and hardening. Use when implementing or auditing least-privilege execution, approval-first elevated access, automatic privilege drop after privileged tasks, idle timeout controls for elevated/root sessions, and monitoring listening ports for insecure or unapproved exposure.
---

# Cyber Security Engineer

Implement these controls in every security-sensitive task:

1. Keep default execution in normal (non-root) mode.
2. Request explicit user approval before any elevated command.
3. Scope elevation to the minimum command set required for the active task.
4. Drop elevated state immediately after the privileged command completes.
5. Expire elevated state after 30 idle minutes and require re-approval.
6. Monitor listening network ports and flag insecure or unapproved exposure.
7. If no approved baseline exists, generate one with `python3 scripts/generate_approved_ports.py`, then review and prune.
8. Benchmark controls against ISO 27001 and NIST and report violations with mitigations.

## Non-Goals (Web Browsing)

- Do not use web browsing / web search as part of this skill. Keep assessments and recommendations based on local host/OpenClaw state and the bundled references in this skill.

## Files To Use

- `references/least-privilege-policy.md`: Operational policy and acceptance checks.
- `references/port-monitoring-policy.md`: Network port monitoring policy and remediation guidance.
- `references/compliance-controls-map.json`: ISO 27001 and NIST control mapping catalog.
- `scripts/root_session_guard.py`: Stateful idle-timeout and elevation-session helper.
- `scripts/guarded_privileged_exec.py`: Wrapper that enforces approval-first elevated execution and immediate privilege drop.
- `scripts/install-openclaw-runtime-hook.sh`: Installs a runtime sudo guard wrapper for OpenClaw.
- `scripts/port_monitor.py`: Listening-port inventory, insecure-port detection, and recommendations.
- `scripts/generate_approved_ports.py`: Create an approved listening-port baseline from current services.
- `references/approved_ports.template.json`: Starter baseline template.
- `scripts/compliance_dashboard.py`: Assessment scaffold and dashboard renderer for controls map, violations, risk, and mitigations.
- `scripts/live_assessment.py`: Populate assessment findings from current machine/OpenClaw runtime state.

## Workflow

1. Validate current policy against `references/least-privilege-policy.md`.
2. Before privileged execution, run:
   - `python3 scripts/root_session_guard.py --timeout-minutes 30 preflight`
3. If preflight says `REQUIRES_APPROVAL`, stop and ask the user for approval.
4. If user approves, run privileged command, then immediately run:
   - `python3 scripts/root_session_guard.py elevated-used`
   - Execute privileged action
   - `python3 scripts/root_session_guard.py drop`
5. For non-privileged work, keep state in normal mode and run:
   - `python3 scripts/root_session_guard.py normal-used`
6. Run network exposure monitoring:
   - `python3 scripts/port_monitor.py --json`
7. If no approved baseline exists, generate one:
   - `python3 scripts/generate_approved_ports.py`
8. Report insecure or unapproved ports and recommend secure alternatives.
9. Initialize assessment scaffold:
   - `python3 scripts/compliance_dashboard.py init-assessment --system "OpenClaw"`
10. Update assessment values based on observed controls and evidence.
11. Render dashboard views:
   - `python3 scripts/compliance_dashboard.py render`
12. For auto-run mode, execute periodic cycle from repo root:
   - `./scripts/auto-invoke-security-cycle.sh`
13. Enable cross-platform scheduler auto-invoke from repo root:
   - `./scripts/enable-auto-invoke.sh`

## Preferred Privileged Executor

Use this wrapper for elevated commands:

`python3 scripts/guarded_privileged_exec.py --reason "why root is needed" --use-sudo -- <command>`

Behavior:

1. Authorizes the exact command argv against an elevated allowlist.
2. Prompts for approval if the argv is not already allowlisted for the current elevated session.
3. Adds the argv to the allowlist for the current task session (least privilege).
4. Executes the command (no `shell=True`; argv-safe execution).
5. Drops elevation after command completion by default (use `--keep-session` only when a task needs multiple privileged steps).

## Required Behaviors

- Never keep root/elevated access open between unrelated tasks.
- Never execute root commands without an explicit approval step in the current flow.
- If timeout is exceeded, force session expiration and approval renewal.
- Log all state transitions with UTC timestamps in the session state file.
- Flag listening ports not present in the approved baseline.
- Prompt for secure alternatives when insecure ports are detected.
- Maintain control assessment status as compliant/partial/violation/not_assessed.
- Include risk and mitigation ownership in dashboard outputs.

## Output Contract

When reporting status to the user, include:

1. Current privilege state (`normal` or `elevated`).
2. Time since last elevated activity.
3. Whether approval is currently required.
4. What action was taken (`continue-normal`, `request-approval`, or `drop-elevation`).
5. Port-monitoring summary (listening services, unapproved ports, insecure ports, recommended secure ports/protocols).
6. Compliance dashboard summary (control map coverage, violations, risk counts, and mitigation plan).
