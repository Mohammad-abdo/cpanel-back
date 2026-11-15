# TASK-013 independent review packet
Task: TASK-013: Error groups and alert lifecycle. Phase: 04 - Observability & Project Logs. Recorded status in task file: PLANNED. This packet does NOT change status; no review, pass or DONE is recorded here.
## Objective
Deliver Error groups and alert lifecycle for NodeTeam Control. Scope: First/last/count, deploy comparison, thresholds/dedup/ack/escalation.
## Acceptance criteria (copied from docs/PLAN/TASKS/TASK-013.md)
Check repeated errors/intermittent thresholds/no-data; no automatic developer blame.
## Implementation files
- apps/api/src/modules/monitoring/ (rules, alerts, error groups)
## Tests and evidence
- apps/api/tests/phase4-observability.test.js (17 tests)
- Test files may be shared with other tasks; counts are per file. Full suite last run locally 2026-11-15: 29 files, 292 tests passed (in-memory Prisma double).
- Evidence: docs/TEST/TASKS/TASK-013-TEST.md
- Evidence: docs/REVIEW/TASKS/TASK-013-SELF-REVIEW.md (SELF_REVIEW, not independent)
- Covered: repeated-error threshold with dedup, auto-resolve and reopen; intermittent threshold across buckets (a single burst does not fire); no-data only when a log source exists, otherwise unknown; acknowledge, escalate and manual resolve with audit and scope checks; Owner-only rules; deployment...
## Acceptance coverage
- Criteria with local test evidence: see Covered/PASS rows in the TEST record; map each criterion to a test name during review (not done here).
- NOT_RUN or open items recorded in the TEST record:
  - ## NOT_RUN
  - Notification delivery (email/Telegram) of escalations: NOT_RUN; only an in-app Notification row for Owners is created.
  - A scheduler that calls `evaluateAll` and `escalateDue`: NOT_RUN (worker hook still absent).
  - Live HTTP/SSE against a database and a real browser EventSource: NOT_RUN. Production verification: not claimed.
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
