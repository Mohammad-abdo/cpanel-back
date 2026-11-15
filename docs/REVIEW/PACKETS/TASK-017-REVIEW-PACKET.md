# TASK-017 independent review packet
Task: TASK-017: Operation queue and approval workflow. Phase: 03 - Project & Deployment Management. Recorded status in task file: PLANNED. This packet does NOT change status; no review, pass or DONE is recorded here.
## Objective
Deliver Operation queue and approval workflow for NodeTeam Control. Scope: OperationJob/Execution/ApprovalRequest, BullMQ/cancel/impact preview.
## Acceptance criteria (copied from docs/PLAN/TASKS/TASK-017.md)
High/Critical policy enforced; retry side effects not duplicated; canceled/expired/denied/timeout outcomes audited.
## Implementation files
- apps/api/src/modules/operations/
- apps/worker/src/
## Tests and evidence
- apps/api/tests/phase3-operations.test.js (17 tests)
- apps/api/tests/worker-scheduler.test.js (7 tests)
- Test files may be shared with other tasks; counts are per file. Full suite last run locally 2026-11-15: 29 files, 292 tests passed (in-memory Prisma double).
- Evidence: docs/TEST/TASKS/TASK-017-TEST.md
- Evidence: docs/REVIEW/TASKS/TASK-017-SELF-REVIEW.md (SELF_REVIEW, not independent)
- Covered: High/Critical escalation (production, rollback) to PENDING_APPROVAL; separation of duties; unauthorized and wrong-environment denial; cross-project environment rejection; idempotency replay and conflict; secret redaction in payload; denied, cancelled, expired and timeout outcomes audited...
## Acceptance coverage
- Criteria with local test evidence: see Covered/PASS rows in the TEST record; map each criterion to a test name during review (not done here).
- NOT_RUN or open items recorded in the TEST record:
  - ## NOT_RUN
  - BullMQ queue and worker: not run, dependency not installed (REQUIRES DECISION, see self-review).
  - Agent-side execution (git pull, pm2 restart, rollback) on a real server: NOT_RUN. The default executor is simulated.
  - HTTP route integration against a live database: NOT_RUN.
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
