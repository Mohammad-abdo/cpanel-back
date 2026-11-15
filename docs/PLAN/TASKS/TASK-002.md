# TASK-002: Prisma MySQL API and Agent contracts

## Status
PLANNED
## Priority
HIGH
## Phase
00 - Discovery & Technical Foundation
## Objective
Deliver Prisma MySQL API and Agent contracts for NodeTeam Control.
## Requirements
required.md sections 2,7,10,11; [traceability](../REQUIREMENTS-TRACEABILITY.md).
## Dependencies
TASK-001. No waiver or reordering without explicit user approval.
## Scope
All model relationships/indexes; /api/v1 DTOs; Agent mTLS job envelope.
## Out of Scope
Unrelated features, stack changes and unauthorized production changes. Demo data is not inventory evidence.
## Affected Modules
Source phase-specific API/web/worker/Agent modules; identify exact files before implementation. Phase00 changes specifications only. Each backend module owns controller/validator/service/routes; Prisma/MySQL stores metadata.
## Implementation Steps
Define scoped contracts; verify prerequisites; implement only this capability; execute checks; update documentation and evidence.
## Security Considerations
Resource/environment authorization; secret redaction; actor separation/audit; replay protection for operations; read-only discovery.
## Acceptance Criteria
Validate FK/delete rules, scoped contracts, idempotency, actor roles, expiry/replay examples.
## Test Plan
Exercise the acceptance scenarios above with isolated fixtures, success and negative cases; record expected/actual/evidence. Current state NOT_RUN unless a separate report states otherwise.
## Risks
Unknown environment/version/policy remains UNKNOWN or REQUIRES DECISION; no invented evidence.
## Review Requirements
Label SELF_REVIEW honestly; complete independent gate where required before closure.
## Deliverables
Scoped specifications/implementation, tests and review evidence, updated traceability; DONE only after gates.
