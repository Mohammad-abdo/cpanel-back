# TASK-005: Sessions MFA login and Owner protection

## Status
PLANNED
## Priority
HIGH
## Phase
01 - Core Platform & Authentication
## Objective
Deliver Sessions MFA login and Owner protection for NodeTeam Control.
## Requirements
required.md sections 7,11,14; [traceability](../REQUIREMENTS-TRACEABILITY.md).
## Dependencies
TASK-004. No waiver or reordering without explicit user approval.
## Scope
User/Session/MfaFactor, login/mfa/logout, expiry/revocation/recovery.
## Out of Scope
Unrelated features, stack changes and unauthorized production changes. Demo data is not inventory evidence.
## Affected Modules
Source phase-specific API/web/worker/Agent modules; identify exact files before implementation. Phase00 changes specifications only. Each backend module owns controller/validator/service/routes; Prisma/MySQL stores metadata.
## Implementation Steps
Define scoped contracts; verify prerequisites; implement only this capability; execute checks; update documentation and evidence.
## Security Considerations
Resource/environment authorization; secret redaction; actor separation/audit; replay protection for operations; read-only discovery.
## Acceptance Criteria
No access before MFA; reject bad credentials/CSRF/expired sessions/Owner escalation.
## Test Plan
Exercise the acceptance scenarios above with isolated fixtures, success and negative cases; record expected/actual/evidence. Current state NOT_RUN unless a separate report states otherwise.
## Risks
Unknown environment/version/policy remains UNKNOWN or REQUIRES DECISION; no invented evidence.
## Review Requirements
Label SELF_REVIEW honestly; complete independent gate where required before closure.
## Deliverables
Scoped specifications/implementation, tests and review evidence, updated traceability; DONE only after gates.
