# TASK-001: Ubuntu inventory and security recovery baseline

## Status
IN_PROGRESS
## Priority
HIGH
## Phase
00 - Discovery & Technical Foundation
## Objective
Deliver Ubuntu inventory and security recovery baseline for NodeTeam Control.
## Requirements
required.md sections 3,14,15; [traceability](../REQUIREMENTS-TRACEABILITY.md).
## Dependencies
None. No waiver or reordering without explicit user approval.
## Scope
Resources, projects, PM2/Laravel/Apache, ports, engines, backups, RPO/RTO.
## Out of Scope
Unrelated features, stack changes and unauthorized production changes. Demo data is not inventory evidence.
## Affected Modules
Source phase-specific API/web/worker/Agent modules; identify exact files before implementation. Phase00 changes specifications only. Each backend module owns controller/validator/service/routes; Prisma/MySQL stores metadata.
## Implementation Steps
Define scoped contracts; verify prerequisites; implement only this capability; execute checks; update documentation and evidence.
## Security Considerations
Resource/environment authorization; secret redaction; actor separation/audit; replay protection for operations; read-only discovery.
## Acceptance Criteria
Evidence-backed read-only inventory; unknowns explicit; no project-path changes.
## Test Plan
Exercise the acceptance scenarios above with isolated fixtures, success and negative cases; record expected/actual/evidence. Current state NOT_RUN unless a separate report states otherwise.
## Risks
Unknown environment/version/policy remains UNKNOWN or REQUIRES DECISION; no invented evidence.
## Review Requirements
Label SELF_REVIEW honestly; complete independent gate where required before closure.
## Deliverables
Scoped specifications/implementation, tests and review evidence, updated traceability; DONE only after gates.
