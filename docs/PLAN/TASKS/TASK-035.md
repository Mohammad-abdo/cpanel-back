# TASK-035: Add server by SSH host and password

## Status
IN_PROGRESS
## Priority
HIGH
## Phase
10 - Owner operations extensions (added 2026-11-15 by Owner request)
## Objective
Register a server by SSH host, port, username and password, test the connection, and keep the credential for later access.
## Requirements
Owner request 2026-11-15; see [DECISIONS](../../DECISIONS.md) (Owner decision 2026-11-15).
## Dependencies
TASK-008.
## Scope
ServerCredential (AES-256-GCM encrypted password, host key fingerprint pinned on first connect), POST /servers/ssh, test/update/remove credential.
## Out of Scope
Changes to other roles' permissions; production execution without the Owner's explicit authorization.
## Security Considerations
Owner only + MFA; password encrypted with CREDENTIAL_ENCRYPTION_KEY (fails closed when missing); never returned by the API or written to logs/audit; host key change is refused (possible man-in-the-middle). Owner accepted the risk that a panel breach exposes stored server passwords.
## Acceptance Criteria
Wrong password and unreachable host rejected without creating the server; password never in responses/audit; host key mismatch refused; non-owner denied.
## Test Plan
Unit tests with fakes, integration tests against a real SSH protocol test server, live API checks; record expected/actual/evidence.
## Review Requirements
SELF_REVIEW labelled honestly; independent review before DONE.
