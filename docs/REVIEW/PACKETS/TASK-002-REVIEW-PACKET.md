# TASK-002 independent review packet
Task: TASK-002: Prisma MySQL API and Agent contracts. Phase: 00 - Discovery & Technical Foundation. Recorded status in task file: PLANNED. This packet does NOT change status; no review, pass or DONE is recorded here.
## Objective
Deliver Prisma MySQL API and Agent contracts for NodeTeam Control. Scope: All model relationships/indexes; /api/v1 DTOs; Agent mTLS job envelope.
## Acceptance criteria (copied from docs/PLAN/TASKS/TASK-002.md)
Validate FK/delete rules, scoped contracts, idempotency, actor roles, expiry/replay examples.
## Implementation files
- apps/api/prisma/schema.prisma
- docs/04-DATABASE-SCHEMA.md
- docs/05-API-CONTRACTS.md
- docs/06-AGENT-SPECIFICATION.md
- docs/openapi.json (generated)
- packages/shared-contracts/src/
## Tests and evidence
- No automated test files map to this task (documentation/specification task).
- Test files may be shared with other tasks; counts are per file. Full suite last run locally 2026-11-15: 29 files, 292 tests passed (in-memory Prisma double).
- Evidence: docs/TEST/TASKS/TASK-002-TEST.md
- Evidence: docs/REVIEW/TASKS/TASK-002-SELF-REVIEW.md (SELF_REVIEW, not independent)
## Acceptance coverage
- No automated test evidence; criteria are documentation-based and unverified.
- NOT_RUN or open items recorded in the TEST record:
  - Open decisions listed as UNKNOWN/REQUIRES DECISION | Manual | PASS | 
  - `prisma migrate` / DB apply | — | NOT_RUN | 
  - Runtime API/Agent tests | — | NOT_RUN | 
## Simulated vs real
- Simulated: Prisma is an in-memory double in tests; executors, DNS, ACME, backup storage and agent actions are simulated unless the TEST record says otherwise. Real: local dev API/MySQL runs only where the TEST record states them. Production: not verified.
## Open risks
- Dependencies not installed or REQUIRES DECISION items (for example BullMQ, mTLS, Loki, Wazuh, Restic) remain open; see the SELF_REVIEW file.
## Reviewer checklist
- [ ] Acceptance criteria independently re-derived and each mapped to a test or evidence file
- [ ] Tests re-run by reviewer (command and result recorded in docs/TEST)
- [ ] Simulated components confirmed as labelled; no production claim
- [ ] AGENTS.md rules checked (module layout, Zod validators, no secrets, English only)
- [ ] Open risks and NOT_RUN items accepted, deferred or turned into tasks
Reviewer name: ____  Date: ____  Verdict: ____ (leave blank until a human completes the review)
