# TASK-039: cPanel-style home page

## Status
IN_PROGRESS
## Priority
HIGH
## Phase
10 - Owner operations extensions (added 2026-11-15 by Owner request)
## Objective
Redesign the home page like a hosting control panel home: tool sections with icons, a tool search, and a side column with account and server information.
## Requirements
Owner request 2026-11-15; see [DECISIONS](../../DECISIONS.md).
## Dependencies
TASK-033.
## Scope
Grouped tool sections (Servers, Files, Projects, Domains, Databases, Security, Monitoring, Team, Preferences), search across tools, general information and statistics column, recent activity.
## Out of Scope
Production execution without the Owner's explicit authorization.
## Security Considerations
Links only; each page keeps its own permission checks.
## Acceptance Criteria
All tools reachable; search filters tools in both languages; works at phone width; EN/AR complete.
## Test Plan
Unit tests with fakes, integration tests against the SSH protocol test server where SSH is involved, live API checks; record expected/actual/evidence.
## Review Requirements
SELF_REVIEW labelled honestly; independent review before DONE.
