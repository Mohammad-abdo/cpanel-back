# TASK-034: Create a database when adding a project

## Status
IN_PROGRESS
## Priority
HIGH
## Phase
10 - Owner operations extensions (added 2026-11-15 by Owner request)
## Objective
Optionally create a database and user for a new project from the New project form.
## Requirements
Owner request 2026-11-15; see [DECISIONS](../../DECISIONS.md) (Owner decision 2026-11-15).
## Dependencies
TASK-022.
## Scope
'Create database' option on the New project form: database server, environment, database name; uses POST /databases (approval flow unchanged).
## Out of Scope
Changes to other roles' permissions; production execution without the Owner's explicit authorization.
## Security Considerations
Database creation stays High risk and needs a second approver; the user password is shown once and never stored.
## Acceptance Criteria
Project created with database request; 202 approval shown clearly; validation of database names; denied without permission.
## Test Plan
Unit tests with fakes, integration tests against a real SSH protocol test server, live API checks; record expected/actual/evidence.
## Review Requirements
SELF_REVIEW labelled honestly; independent review before DONE.
