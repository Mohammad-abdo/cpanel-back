# TASK-033: Management home with shortcuts

## Status
IN_PROGRESS
## Priority
HIGH
## Phase
10 - Owner operations extensions (added 2026-11-15 by Owner request)
## Objective
One home page with shortcuts to every management task.
## Requirements
Owner request 2026-11-15; see [DECISIONS](../../DECISIONS.md) (Owner decision 2026-11-15).
## Dependencies
None (UI over existing API).
## Scope
Overview quick-action grid: add server, new project, domains, SSL, databases, backups, files, terminal, deploy, logs, incidents, approvals (pending count), access reviews, reports.
## Out of Scope
Changes to other roles' permissions; production execution without the Owner's explicit authorization.
## Security Considerations
Shortcuts only link to pages; every action keeps its own authorization.
## Acceptance Criteria
Every shortcut opens the right page; pending approvals count shown; works at phone width; EN/AR.
## Test Plan
Unit tests with fakes, integration tests against a real SSH protocol test server, live API checks; record expected/actual/evidence.
## Review Requirements
SELF_REVIEW labelled honestly; independent review before DONE.
