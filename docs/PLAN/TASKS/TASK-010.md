# TASK-010: Server monitoring dashboard

## Status
PLANNED
## Priority
HIGH
## Phase
02 - Server Agents & Monitoring
## Objective
Deliver Server monitoring dashboard for NodeTeam Control.
## Requirements
required.md sections 3,13; [traceability](../REQUIREMENTS-TRACEABILITY.md).
## Dependencies
TASK-009. No waiver or reordering without explicit user approval.
## Scope
Prometheus CPU/RAM/swap/disk/network and health/connectivity.
## Out of Scope
Unrelated features, stack changes and unauthorized production changes. Demo data is not inventory evidence.
## Affected Modules
Source phase-specific API/web/worker/Agent modules; identify exact files before implementation. Phase00 changes specifications only. Each backend module owns controller/validator/service/routes; Prisma/MySQL stores metadata.
## Implementation Steps
Define scoped contracts; verify prerequisites; implement only this capability; execute checks; update documentation and evidence.
## Security Considerations
Resource/environment authorization; secret redaction; actor separation/audit; replay protection for operations; read-only discovery.
## Acceptance Criteria
Check metric fixtures/no-data/stale/disconnected/scoped access and adjustable sampling.
## Test Plan
Exercise the acceptance scenarios above with isolated fixtures, success and negative cases; record expected/actual/evidence. Current state NOT_RUN unless a separate report states otherwise.
## Risks
Unknown environment/version/policy remains UNKNOWN or REQUIRES DECISION; no invented evidence.
## Review Requirements
Label SELF_REVIEW honestly; complete independent gate where required before closure.
## Deliverables
Scoped specifications/implementation, tests and review evidence, updated traceability; DONE only after gates.
