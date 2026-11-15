# TASK-011: Loki project log ingestion and redaction

## Status
PLANNED
## Priority
HIGH
## Phase
04 - Observability & Project Logs
## Objective
Deliver Loki project log ingestion and redaction for NodeTeam Control.
## Requirements
required.md sections 4,13; [traceability](../REQUIREMENTS-TRACEABILITY.md).
## Dependencies
TASK-019. No waiver or reordering without explicit user approval.
## Scope
Application/runtime/web/database/deployment/jobs/security/audit sources.
## Out of Scope
Unrelated features, stack changes and unauthorized production changes. Demo data is not inventory evidence.
## Affected Modules
Source phase-specific API/web/worker/Agent modules; identify exact files before implementation. Phase00 changes specifications only. Each backend module owns controller/validator/service/routes; Prisma/MySQL stores metadata.
## Implementation Steps
Define scoped contracts; verify prerequisites; implement only this capability; execute checks; update documentation and evidence.
## Security Considerations
Resource/environment authorization; secret redaction; actor separation/audit; replay protection for operations; read-only discovery.
## Acceptance Criteria
Injected test error reaches correct scoped project; tokens absent before storage and display.
## Test Plan
Exercise the acceptance scenarios above with isolated fixtures, success and negative cases; record expected/actual/evidence. Current state NOT_RUN unless a separate report states otherwise.
## Risks
Unknown environment/version/policy remains UNKNOWN or REQUIRES DECISION; no invented evidence.
## Review Requirements
Label SELF_REVIEW honestly; complete independent gate where required before closure.
## Deliverables
Scoped specifications/implementation, tests and review evidence, updated traceability; DONE only after gates.
