# Runbook: emergency Owner access (break-glass)

Status: DRAFT, NOT_RUN.

## When to use
Only when normal approval is impossible, for example the second approver is unreachable during an outage. It is not a shortcut for routine changes.

## How it works
- Only a signed-in Owner with MFA can call `POST /platform/break-glass/activate`.
- The Owner supplies a reason (at least 10 characters), a duration of 5 to 60 minutes and the offline recovery code. The server compares the SHA-256 of the code with `EMERGENCY_RECOVERY_CODE_SHA256` using a constant-time comparison.
- Five failed attempts in 15 minutes lock activation, even for the correct code.
- Activation and ending are written to the audit log as critical events. The recovery code is never stored or logged.
- `GET /platform/break-glass` reports whether a window is active. `POST /platform/break-glass/end` closes it early.

## Limits (be honest)
The window is recorded and reported. The permission system does not yet widen access during the window, so privileged actions still follow their normal gates. Wiring enforcement into rbac is open work.

## After use
Review the audit trail, rotate the recovery code (needs explicit Owner authorization), and record the event in the incident log.
