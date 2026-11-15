# TASK-018 independent review packet
Task: TASK-018: Project discovery Git runtime and deployment. Phase: 03 - Project & Deployment Management. Recorded status in task file: PLANNED. This packet does NOT change status; no review, pass or DONE is recorded here.
## Objective
Deliver Project discovery Git runtime and deployment for NodeTeam Control. Scope: Project/environment/runtime/repository/types/secret configuration/PM2 lifecycle.
## Acceptance criteria (copied from docs/PLAN/TASKS/TASK-018.md)
Discover without redeploy/path changes; test Node/Laravel staging, build failure, denied lifecycle and redaction.
## Implementation files
- apps/api/src/modules/projects/
- apps/api/src/modules/deployments/
## Tests and evidence
- apps/api/tests/phase3-projects-deployments.test.js (21 tests)
- apps/api/tests/phase3-operations.test.js (17 tests)
- Test files may be shared with other tasks; counts are per file. Full suite last run locally 2026-11-15: 29 files, 292 tests passed (in-memory Prisma double).
- Evidence: docs/TEST/TASKS/TASK-018-TEST.md
- Evidence: docs/REVIEW/TASKS/TASK-018-SELF-REVIEW.md (SELF_REVIEW, not independent)
- Covered: read-only discovery (no deployment, no existing-project mutation, no operations created), Owner-only create/configure/archive, duplicate slug, secret names only (values rejected, metadata redacted), git credential stripping, member-only visibility, PM2 lifecycle through the operation que...
## Acceptance coverage
- Criteria with local test evidence: see Covered/PASS rows in the TEST record; map each criterion to a test name during review (not done here).
- NOT_RUN or open items recorded in the TEST record:
  - ## NOT_RUN
  - Agent-side git pull, build, pm2 reload and rollback on a real server: NOT_RUN (runner and health checker are simulated ports).
  - Live HTTP and database integration: NOT_RUN. Production verification: not claimed.
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
