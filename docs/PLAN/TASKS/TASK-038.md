# TASK-038: Server details page with full control

## Status
IN_PROGRESS
## Priority
HIGH
## Phase
10 - Owner operations extensions (added 2026-11-15 by Owner request)
## Objective
One page per server showing everything about it, with every action available from that page.
## Requirements
Owner request 2026-11-15; see [DECISIONS](../../DECISIONS.md).
## Dependencies
TASK-035, TASK-036.
## Scope
Tabs: overview (status, metrics history, live system info over SSH: OS, uptime, load, memory, disks, top processes), services (start/stop/restart/status over SSH), ports and firewall (rules, preview, apply with approval), projects, domains, databases, security events, files, terminal, settings (SSH login test/replace/remove, agent enrollment/revoke). API: GET /servers/:id/ssh/info, POST /servers/:id/ssh/service.
## Out of Scope
Production execution without the Owner's explicit authorization.
## Security Considerations
Owner only for SSH actions + MFA; service names validated against a strict pattern and passed as a single argument (no shell injection); every action audited; firewall keeps its approval flow.
## Acceptance Criteria
Every tab loads from the API; service actions run over real SSH in tests; invalid service names rejected; non-owner denied; EN/AR.
## Test Plan
Unit tests with fakes, integration tests against the SSH protocol test server where SSH is involved, live API checks; record expected/actual/evidence.
## Review Requirements
SELF_REVIEW labelled honestly; independent review before DONE.
