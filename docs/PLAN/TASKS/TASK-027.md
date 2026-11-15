# TASK-027: Incident lifecycle evidence and ownership

## Status
PLANNED
## Priority
HIGH
## Phase
08 - Advanced Security & Operations
## Objective
Deliver Incident lifecycle evidence and ownership for NodeTeam Control.
## Requirements
required.md sections 9; [traceability](../REQUIREMENTS-TRACEABILITY.md).
## Dependencies
TASK-026. No waiver or reordering without explicit user approval.
## Scope
Detected/Triaged/Assigned/Investigating/Contained/Resolved/Closed.
## Out of Scope
Unrelated features, stack changes and unauthorized production changes. Demo data is not inventory evidence.
## Affected Modules
Source phase-specific API/web/worker/Agent modules; identify exact files before implementation. Phase00 changes specifications only. Each backend module owns controller/validator/service/routes; Prisma/MySQL stores metadata.
## Implementation Steps
Define scoped contracts; verify prerequisites; implement only this capability; execute checks; update documentation and evidence.
## Security Considerations
Resource/environment authorization; secret redaction; actor separation/audit; replay protection for operations; read-only discovery.
## Acceptance Criteria
Reject invalid transition/assignment; preserve severity/owner/evidence/action timestamps and reopened policy.
## Test Plan
Exercise the acceptance scenarios above with isolated fixtures, success and negative cases; record expected/actual/evidence. Current state NOT_RUN unless a separate report states otherwise.
## Risks
Unknown environment/version/policy remains UNKNOWN or REQUIRES DECISION; no invented evidence.
## Review Requirements
Label SELF_REVIEW honestly; complete independent gate where required before closure.
## Deliverables
Scoped specifications/implementation, tests and review evidence, updated traceability; DONE only after gates.
