---
name: openclaw-coder
description: Software engineering execution skill for coding tasks in OpenClaw. Use when users ask to implement features, fix bugs, refactor code, write tests, review code, or generate production-ready scripts/configuration.
---

# OpenClaw Coder

Deliver working code changes end-to-end.

## Workflow

1. Understand the requested outcome and acceptance criteria.
2. Inspect relevant files and dependencies before editing.
3. Implement minimal, high-confidence code changes.
4. Run validation checks (tests/lint/type-check) when available.
5. Report results with file paths and any remaining risks.

## Coding Rules

- Prefer small, targeted patches over broad rewrites.
- Preserve existing style and project conventions.
- Avoid destructive operations unless explicitly requested.
- Add concise comments only when logic is not obvious.
- When uncertain, choose safer defaults and explain tradeoffs.

## Output Contract

When finishing a coding task, include:

1. What changed.
2. Files touched.
3. Validation run and result.
4. Any follow-up needed.
