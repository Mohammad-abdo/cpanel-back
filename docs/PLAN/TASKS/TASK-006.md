# TASK-006: Resource permissions and team management

## Status
PLANNED
## Priority
HIGH
## Phase
01 - Core Platform & Authentication
## Objective
Deliver Resource permissions and team management for NodeTeam Control.
## Requirements
required.md sections 5,7; [traceability](../REQUIREMENTS-TRACEABILITY.md).
## Dependencies
TASK-005. No waiver or reordering without explicit user approval.
## Scope
Roles/grants/Team/TeamMember/ProjectMember with action/resource/environment.
## Out of Scope
Unrelated features, stack changes and unauthorized production changes. Demo data is not inventory evidence.
## Affected Modules
Source phase-specific API/web/worker/Agent modules; identify exact files before implementation. Phase00 changes specifications only. Each backend module owns controller/validator/service/routes; Prisma/MySQL stores metadata.
## Implementation Steps
Define scoped contracts; verify prerequisites; implement only this capability; execute checks; update documentation and evidence.
## Security Considerations
Resource/environment authorization; secret redaction; actor separation/audit; replay protection for operations; read-only discovery.
## Acceptance Criteria
Reject cross-project and staging-to-production access; prevent Team Lead scope expansion.
## Test Plan
Exercise the acceptance scenarios above with isolated fixtures, success and negative cases; record expected/actual/evidence. Current state NOT_RUN unless a separate report states otherwise.
## Risks
Unknown environment/version/policy remains UNKNOWN or REQUIRES DECISION; no invented evidence.
## Review Requirements
Label SELF_REVIEW honestly; complete independent gate where required before closure.
## Deliverables
Scoped specifications/implementation, tests and review evidence, updated traceability; DONE only after gates.
