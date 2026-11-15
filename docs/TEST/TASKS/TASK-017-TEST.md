# TASK-017 test evidence

Date: 2026-11-15. Environment: local Windows workspace, Vitest with an in-memory Prisma double (`apps/api/tests/phase3-helpers.js`).

| Check | Command | Result |
| --- | --- | --- |
| Operation queue and approval unit tests | `cd apps/api && npx vitest run tests/phase3-operations.test.js` | 17 passed, 0 failed |

Covered: High/Critical escalation (production, rollback) to PENDING_APPROVAL; separation of duties; unauthorized and wrong-environment denial; cross-project environment rejection; idempotency replay and conflict; secret redaction in payload; denied, cancelled, expired and timeout outcomes audited; retry does not repeat a successful side effect; failed attempt retried with new attemptId; simulated default executor; impact preview; expiry sweeper.

## NOT_RUN

- BullMQ queue and worker: not run, dependency not installed (REQUIRES DECISION, see self-review).
- Agent-side execution (git pull, pm2 restart, rollback) on a real server: NOT_RUN. The default executor is simulated.
- HTTP route integration against a live database: NOT_RUN.
- Production verification: not claimed.
