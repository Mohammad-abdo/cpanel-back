# TASK-014 independent review packet
Task: TASK-014: Member profile timeline and identity mapping. Phase: 05 - Team Intelligence & Reporting. Recorded status in task file: PLANNED. This packet does NOT change status; no review, pass or DONE is recorded here.
## Objective
Deliver Member profile timeline and identity mapping for NodeTeam Control. Scope: Assignments/grants/deploy/restart/config/denials/approvals/incidents/last activity.
## Acceptance criteria (copied from docs/PLAN/TASKS/TASK-014.md)
Separate initiator/approver/executor; unmapped SSH/Git remains Unattributed; link original events.
## Implementation files
- apps/api/src/modules/members/
## Tests and evidence
- apps/api/tests/phase5-members.test.js (7 tests)
- Test files may be shared with other tasks; counts are per file. Full suite last run locally 2026-11-15: 29 files, 292 tests passed (in-memory Prisma double).
- Evidence: docs/TEST/TASKS/TASK-014-TEST.md
- Evidence: docs/REVIEW/TASKS/TASK-014-SELF-REVIEW.md (SELF_REVIEW, not independent)
- Covered: initiator/approver roles separate with links to original events; denials and config changes as categories; unmapped GitHub/SSH events Unattributed and resolved only after an Owner mapping; Owner-only mapping; profile visible to self and Owner only without password hash; half-open period ...
## Acceptance coverage
- Criteria with local test evidence: see Covered/PASS rows in the TEST record; map each criterion to a test name during review (not done here).
- NOT_RUN or open items recorded in the TEST record:
  - ## NOT_RUN
  - Real SSH/GitHub event collection: NOT_RUN (no collector exists; ActivityEvent rows with metadata.externalIdentity are the assumed input).
  - Live HTTP/browser against Laragon with mapping round-trip: NOT_RUN. Production verification: not claimed.
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
