# Worker Scheduler Test Record

Scope: apps/worker/src/{scheduler,jobs,scheduler-main}.js. Local only; no production verification.

| Command | Result |
|---|---|
| `node --check` on apps/worker/src/*.js | PASS (4 files) |
| `cd apps/api && npx vitest run worker-` | PASS, 1 file, 7 tests (interval, overlap guard, error isolation + audit failure tolerance, shutdown drain, jitter, env config, job-to-service wiring) |
| Import of real service factories via `createDefaultServices()` | PASS (all services constructed; no DB query made) |
| Live run against MySQL (`node src/scheduler-main.js`) | NOT_RUN |
| Real Redis/BullMQ listener alongside scheduler | NOT_RUN |

Review: SELF_REVIEW only; independent review NOT_RUN.
