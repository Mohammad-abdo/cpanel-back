# TASK-032: Modular backend foundation

## Status
IN_REVIEW
## Priority
HIGH
## Phase
Foundation: local API slice of TASK-004.
## Objective
Create runnable Express JavaScript API and enforce requested module boundaries.
## Requirements
Each module has controller, validator, service and routes. Shared validation and errors; runnable health API; module scaffolding.
## Dependencies
User implementation authorization. Local repository inspection complete; production inventory, full schema and UI design are not prerequisites for this isolated slice.
## Scope
npm workspace, health module, Zod environment/input validation, security headers, request IDs, JSON limits, centralized errors, safe module generator, API tests and documentation.
## Out of Scope
Authentication, business CRUD, Prisma persistence, worker execution, frontend and production changes.
## Affected Modules
apps/api, scripts/create-module.mjs, root package configuration, docs.
## Implementation Steps
Document contract; write module boundaries; install dependencies; execute API and scaffold checks; record review and results.
## Security Considerations
Loopback binding by default, no secrets in responses, strict query validation, bounded body, no generated routes auto-mounted, no file overwrite or path traversal in generator.
## Acceptance Criteria
Health GET returns 200 and liveness only. Unknown query returns 400. Unknown path returns 404. Malformed/oversized JSON returns 400/413. Internal errors do not leak details. Environment values validate. Generator creates four files and rejects overwrite/traversal.
## Test Plan
Vitest and Supertest exercise HTTP paths and failures. Generator tests use an isolated temporary workspace. Server startup smoke test on loopback.
## Risks
No persistence or authentication yet; health must not claim dependency readiness.
## Review Requirements
SELF_REVIEW documented; independent review pending.
## Deliverables
Runnable API, module generator, tests, README and review/test records.
