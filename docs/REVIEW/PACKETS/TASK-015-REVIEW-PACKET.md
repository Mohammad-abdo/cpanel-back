# TASK-015 independent review packet
Task: TASK-015: Team and project reports with event lineage. Phase: 05 - Team Intelligence & Reporting. Recorded status in task file: PLANNED. This packet does NOT change status; no review, pass or DONE is recorded here.
## Objective
Deliver Team and project reports with event lineage for NodeTeam Control. Scope: Individual/contribution/deployment/changes/incidents/security/failures/workload/access and project metrics.
## Acceptance criteria (copied from docs/PLAN/TASKS/TASK-015.md)
Recompute fixture aggregates; retries do not double-count; N/A zero denominator; scoped period boundaries.
## Implementation files
- apps/api/src/modules/reports/
## Tests and evidence
- apps/api/tests/phase5-reports.test.js (18 tests)
- Test files may be shared with other tasks; counts are per file. Full suite last run locally 2026-11-15: 29 files, 292 tests passed (in-memory Prisma double).
- Evidence: docs/TEST/TASKS/TASK-015-TEST.md
- Evidence: docs/REVIEW/TASKS/TASK-015-SELF-REVIEW.md (SELF_REVIEW, not independent)
- Covered: fixture aggregates recomputed by hand, lineage ids equal the source rows, half-open period boundaries, N/A for zero denominators, retries and duplicate rows counted once, individual report initiator versus approver, contribution/changes/security/workload/access reports, scoped authorizat...
## Acceptance coverage
- Criteria with local test evidence: see Covered/PASS rows in the TEST record; map each criterion to a test name during review (not done here).
- NOT_RUN or open items recorded in the TEST record:
  - ## NOT_RUN
  - Uptime, latency, request-rate, slow-query and backup-verification sections of required.md section 6: NOT_RUN and not implemented (their data sources are Prom...
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
