# TASK-006 independent review packet
Task: TASK-006: Resource permissions and team management. Phase: 01 - Core Platform & Authentication. Recorded status in task file: PLANNED. This packet does NOT change status; no review, pass or DONE is recorded here.
## Objective
Deliver Resource permissions and team management for NodeTeam Control. Scope: Roles/grants/Team/TeamMember/ProjectMember with action/resource/environment.
## Acceptance criteria (copied from docs/PLAN/TASKS/TASK-006.md)
Reject cross-project and staging-to-production access; prevent Team Lead scope expansion.
## Implementation files
- apps/api/src/modules/rbac/
- apps/api/src/modules/teams/
- apps/api/src/modules/users/
- apps/api/src/common/scope.js
- packages/permission-catalog/src/
## Tests and evidence
- apps/api/tests/rbac-roles-evaluation.test.js (11 tests)
- apps/api/tests/rbac-teams.test.js (13 tests)
- apps/api/tests/scope-isolation.test.js (6 tests)
- Test files may be shared with other tasks; counts are per file. Full suite last run locally 2026-11-15: 29 files, 292 tests passed (in-memory Prisma double).
- Evidence: docs/TEST/TASKS/TASK-006-TEST.md
- Evidence: docs/REVIEW/TASKS/TASK-006-SELF-REVIEW.md (SELF_REVIEW, not independent)
## Acceptance coverage
- Criteria with local test evidence: see Covered/PASS rows in the TEST record; map each criterion to a test name during review (not done here).
- NOT_RUN or open items recorded in the TEST record:
  - Cross-project isolation against live data | NOT_RUN | 
  - Route-level (HTTP) tests for /teams and /rbac | NOT_RUN | 
  - Production | NOT_RUN | 
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
