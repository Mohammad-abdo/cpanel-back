# TASK-004: API Web Worker Prisma MySQL foundation

## Status
PLANNED
## Priority
HIGH
## Phase
01 - Core Platform & Authentication
## Objective
Deliver API Web Worker Prisma MySQL foundation for NodeTeam Control.
## Requirements
required.md sections 1,11; [traceability](../REQUIREMENTS-TRACEABILITY.md).
## Dependencies
TASK-003. No waiver or reordering without explicit user approval.
## Scope
Express JavaScript, Prisma/MySQL8, React Vite JSX, BullMQ/Redis.
## Out of Scope
Unrelated features, stack changes and unauthorized production changes. Demo data is not inventory evidence.
## Affected Modules
Source phase-specific API/web/worker/Agent modules; identify exact files before implementation. Phase00 changes specifications only. Each backend module owns controller/validator/service/routes; Prisma/MySQL stores metadata.
## Implementation Steps
Define scoped contracts; verify prerequisites; implement only this capability; execute checks; update documentation and evidence.
## Security Considerations
Resource/environment authorization; secret redaction; actor separation/audit; replay protection for operations; read-only discovery.
## Acceptance Criteria
Prisma validate/generate and isolated migrations; API/DB smoke; web build; worker connection.
## Test Plan
Exercise the acceptance scenarios above with isolated fixtures, success and negative cases; record expected/actual/evidence. Current state NOT_RUN unless a separate report states otherwise.
## Risks
Unknown environment/version/policy remains UNKNOWN or REQUIRES DECISION; no invented evidence.
## Review Requirements
Label SELF_REVIEW honestly; complete independent gate where required before closure.
## Deliverables
Scoped specifications/implementation, tests and review evidence, updated traceability; DONE only after gates.
