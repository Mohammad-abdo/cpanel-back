# TASK-027 independent review packet
Task: TASK-027: Incident lifecycle evidence and ownership. Phase: 08 - Advanced Security & Operations. Recorded status in task file: PLANNED. This packet does NOT change status; no review, pass or DONE is recorded here.
## Objective
Deliver Incident lifecycle evidence and ownership for NodeTeam Control. Scope: Detected/Triaged/Assigned/Investigating/Contained/Resolved/Closed.
## Acceptance criteria (copied from docs/PLAN/TASKS/TASK-027.md)
Reject invalid transition/assignment; preserve severity/owner/evidence/action timestamps and reopened policy.
## Implementation files
- apps/api/src/modules/incidents/
## Tests and evidence
- apps/api/tests/phase8-incidents-security.test.js (16 tests)
- Test files may be shared with other tasks; counts are per file. Full suite last run locally 2026-11-15: 29 files, 292 tests passed (in-memory Prisma double).
- Evidence: docs/TEST/TASKS/TASK-027-TEST.md
- Evidence: docs/REVIEW/TASKS/TASK-027-SELF-REVIEW.md (SELF_REVIEW, not independent)
## Acceptance coverage
- Criteria with local test evidence: see Covered/PASS rows in the TEST record; map each criterion to a test name during review (not done here).
- NOT_RUN or open items recorded in the TEST record:
  - ## NOT_RUN or UNKNOWN
  - Live HTTP calls against the local API for the new routes: NOT_RUN (routes are not mounted yet).
  - Production verification: NOT_RUN. Nothing was executed against a real server, DNS provider, CA, database, backup target, firewall or Wazuh.
  - Independent review and independent test execution: NOT_RUN.
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
