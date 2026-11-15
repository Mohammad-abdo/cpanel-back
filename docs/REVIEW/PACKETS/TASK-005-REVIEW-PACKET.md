# TASK-005 independent review packet
Task: TASK-005: Sessions MFA login and Owner protection. Phase: 01 - Core Platform & Authentication. Recorded status in task file: PLANNED. This packet does NOT change status; no review, pass or DONE is recorded here.
## Objective
Deliver Sessions MFA login and Owner protection for NodeTeam Control. Scope: User/Session/MfaFactor, login/mfa/logout, expiry/revocation/recovery.
## Acceptance criteria (copied from docs/PLAN/TASKS/TASK-005.md)
No access before MFA; reject bad credentials/CSRF/expired sessions/Owner escalation.
## Implementation files
- apps/api/src/modules/auth/
- apps/api/src/modules/users/
- apps/api/src/common/crypto/
- apps/api/src/common/middleware/require-session.js
## Tests and evidence
- apps/api/tests/auth.service.test.js (4 tests)
- apps/api/tests/auth-guard.test.js (3 tests)
- apps/api/tests/totp.test.js (2 tests)
- apps/api/tests/users.service.test.js (4 tests)
- apps/api/tests/security-fixes.test.js (6 tests)
- Test files may be shared with other tasks; counts are per file. Full suite last run locally 2026-11-15: 29 files, 292 tests passed (in-memory Prisma double).
- Evidence: docs/TEST/TASKS/TASK-005-TEST.md
- Evidence: docs/REVIEW/TASKS/TASK-005-SELF-REVIEW.md (SELF_REVIEW, not independent)
## Acceptance coverage
- Criteria with local test evidence: see Covered/PASS rows in the TEST record; map each criterion to a test name during review (not done here).
- NOT_RUN or open items recorded in the TEST record:
  - CSRF | — | NOT_RUN (session bearer model; cookie CSRF later if cookies added) | 
  - Production | — | NOT_RUN | 
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
