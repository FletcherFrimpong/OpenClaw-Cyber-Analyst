# OpenClaw-Cyber-Analyst
This is to ensure your openclaw setup is running securely in your environment. 

## Included Skill

- `cyber-security-engineer/`
  - Least-privilege + approval-first elevated execution
  - 30-minute idle timeout for elevated sessions
  - Port monitoring with insecure-port recommendations
  - ISO 27001 / NIST compliance dashboard scaffold

## Quick Start

```bash
python3 cyber-security-engineer/scripts/port_monitor.py --json
python3 cyber-security-engineer/scripts/compliance_dashboard.py init-assessment --system "OpenClaw"
python3 cyber-security-engineer/scripts/compliance_dashboard.py render
```
