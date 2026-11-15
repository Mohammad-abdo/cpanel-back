# TASK-012 independent review packet
Task: TASK-012: Scoped log search live UI and export. Phase: 04 - Observability & Project Logs. Recorded status in task file: PLANNED. This packet does NOT change status; no review, pass or DONE is recorded here.
## Objective
Deliver Scoped log search live UI and export for NodeTeam Control. Scope: Socket.IO, filters, request/trace/deployment IDs, stack/bookmarks.
## Acceptance criteria (copied from docs/PLAN/TASKS/TASK-012.md)
Reject cross-project subscription/export; verify reconnect/backpressure and gateway-controlled tenancy.
## Implementation files
- apps/api/src/modules/logs/
- apps/web/src/
## Tests and evidence
- apps/api/tests/phase4-logs.test.js (4 tests)
- apps/api/tests/phase4-observability.test.js (17 tests)
- Test files may be shared with other tasks; counts are per file. Full suite last run locally 2026-11-15: 29 files, 292 tests passed (in-memory Prisma double).
- Evidence: docs/TEST/TASKS/TASK-012-TEST.md
- Evidence: docs/REVIEW/TASKS/TASK-012-SELF-REVIEW.md (SELF_REVIEW, not independent)
- Covered: filters (level, request id, trace id, deployment id, text, time), cross-project/wrong-environment/environment-less denial, CSV formula neutralization and audited export, SSE subscription tenancy at subscribe and per event, Last-Event-ID reconnect replay, bounded-queue backpressure with a...
## Acceptance coverage
- Criteria with local test evidence: see Covered/PASS rows in the TEST record; map each criterion to a test name during review (not done here).
- NOT_RUN or open items recorded in the TEST record:
  - ## NOT_RUN
  - Socket.IO transport: not implemented. SSE is used because Socket.IO is not a dependency (REQUIRES DECISION).
  - Real network backpressure on a socket and proxy buffering: NOT_RUN.
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
