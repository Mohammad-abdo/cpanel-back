# TASK-016: Scheduled PDF Excel and weekly monthly summaries

## Status
IN_PROGRESS
## Priority
HIGH
## Phase
05 - Team Intelligence & Reporting
## Objective
Deliver Scheduled PDF Excel and weekly monthly summaries for NodeTeam Control.
## Requirements
required.md sections 5,6; [traceability](../REQUIREMENTS-TRACEABILITY.md).
## Dependencies
TASK-015. No waiver or reordering without explicit user approval.
## Scope
ReportDefinition/Run/Schedule/Artifact and authorized recipients.
## Out of Scope
Unrelated features, stack changes and unauthorized production changes. Demo data is not inventory evidence.
## Affected Modules
Source phase-specific API/web/worker/Agent modules; identify exact files before implementation. Phase00 changes specifications only. Each backend module owns controller/validator/service/routes; Prisma/MySQL stores metadata.
## Implementation Steps
Define scoped contracts; verify prerequisites; implement only this capability; execute checks; update documentation and evidence.
## Security Considerations
Resource/environment authorization; secret redaction; actor separation/audit; replay protection for operations; read-only discovery.
## Acceptance Criteria
Verify retry deduplication, revoked recipient/expired artifact rejection, PDF/Excel parity.
## Test Plan
Exercise the acceptance scenarios above with isolated fixtures, success and negative cases; record expected/actual/evidence. Current state NOT_RUN unless a separate report states otherwise.
## Risks
Unknown environment/version/policy remains UNKNOWN or REQUIRES DECISION; no invented evidence.
## Review Requirements
Label SELF_REVIEW honestly; complete independent gate where required before closure.
## Deliverables
Scoped specifications/implementation, tests and review evidence, updated traceability; DONE only after gates.
