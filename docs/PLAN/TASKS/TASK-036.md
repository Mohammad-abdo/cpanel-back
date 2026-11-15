# TASK-036: Server file manager and web terminal

## Status
IN_PROGRESS
## Priority
HIGH
## Phase
10 - Owner operations extensions (added 2026-11-15 by Owner request)
## Objective
Browse, view, edit, upload, download, rename and delete server files, and open a live terminal, like cPanel.
## Requirements
Owner request 2026-11-15; see [DECISIONS](../../DECISIONS.md) (Owner decision 2026-11-15).
## Dependencies
TASK-035.
## Scope
SFTP-backed file API and a WebSocket terminal (xterm.js) using the stored credential.
## Out of Scope
Changes to other roles' permissions; production execution without the Owner's explicit authorization.
## Security Considerations
Owner only + MFA; one-time short-lived terminal tickets (browser WebSockets cannot send headers); every file change and terminal session audited (input transcript redacted and capped); size limits on view/edit/upload. Replaces the 'No direct dashboard root access' / 'no arbitrary shell' rule for the Owner only (Owner decision 2026-11-15).
## Acceptance Criteria
List/read/write/upload/download/rename/delete work against a real SFTP server; terminal echoes commands; expired/reused ticket refused; non-owner denied; audit rows written.
## Test Plan
Unit tests with fakes, integration tests against a real SSH protocol test server, live API checks; record expected/actual/evidence.
## Review Requirements
SELF_REVIEW labelled honestly; independent review before DONE.
