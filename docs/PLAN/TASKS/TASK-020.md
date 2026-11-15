# TASK-020: Virtual hosts domains and DNS

## Status
IN_PROGRESS
## Priority
HIGH
## Phase
06 - Domains SSL & Database Management
## Objective
Deliver Virtual hosts domains and DNS for NodeTeam Control.
## Requirements
required.md sections 3,11,15; [traceability](../REQUIREMENTS-TRACEABILITY.md).
## Dependencies
TASK-016. No waiver or reordering without explicit user approval.
## Scope
Domain/DnsRecord, Apache/Nginx virtual hosts and provider integration.
## Out of Scope
Unrelated features, stack changes and unauthorized production changes. Demo data is not inventory evidence.
## Affected Modules
Source phase-specific API/web/worker/Agent modules; identify exact files before implementation. Phase00 changes specifications only. Each backend module owns controller/validator/service/routes; Prisma/MySQL stores metadata.
## Implementation Steps
Define scoped contracts; verify prerequisites; implement only this capability; execute checks; update documentation and evidence.
## Security Considerations
Resource/environment authorization; secret redaction; actor separation/audit; replay protection for operations; read-only discovery.
## Acceptance Criteria
Preview diff/impact/approval; test domain/provider failure/config validation/rollback/denied access.
## Test Plan
Exercise the acceptance scenarios above with isolated fixtures, success and negative cases; record expected/actual/evidence. Current state NOT_RUN unless a separate report states otherwise.
## Risks
Unknown environment/version/policy remains UNKNOWN or REQUIRES DECISION; no invented evidence.
## Review Requirements
Label SELF_REVIEW honestly; complete independent gate where required before closure.
## Deliverables
Scoped specifications/implementation, tests and review evidence, updated traceability; DONE only after gates.
