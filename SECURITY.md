# Security Policy

This project is a security control, so weaknesses in it matter. Reports are welcome.

## Reporting a vulnerability

Please report privately, not in a public issue:

1. Open the repository's **Security** tab on GitHub.
2. Choose **Report a vulnerability** and describe the problem.

Include what you ran, what you expected, what happened, and your operating system.
A way to reproduce it is the most useful thing you can send.

You should get a reply within 7 days. Once a fix is released, the report is
credited in the changelog unless you ask otherwise.

## What counts

- A way to run a privileged command without the approval prompt or sudo's password prompt
- A way to make the compliance dashboard report a control as compliant when it is not
- A way to alter the audit log without `audit_logger.py verify` detecting it, short of
  replacing the whole file
- Command injection, path traversal or HTML injection in any script or in the dashboard

## Known limits

Some limits are part of the design and are documented in
[the threat model](cyber-security-engineer/references/threat-model.md). The main
one: an agent running as your own user can read and write your files, so the
controls here that hold against it are the ones the operating system enforces,
chiefly sudo's password prompt. Reports that restate a documented limit are still
welcome if you see a practical way to narrow it.

## Supported versions

Only the latest release receives fixes.
