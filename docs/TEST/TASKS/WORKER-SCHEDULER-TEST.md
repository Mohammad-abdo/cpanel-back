# Job Scheduler Test Record

Scope: cpanel-back/src/jobs/{scheduler,jobs,index}.js (in-process scheduler; replaces the former apps/worker). Local only; no production verification.

| Command | Result |
|---|---|
| `npx vitest run tests/job-scheduler.test.js` | PASS, 7 tests (interval, overlap guard, error isolation + audit failure tolerance, shutdown drain, jitter, env config, job-to-service wiring) |
| Live run inside the API against local MySQL with demo data | PASS: scheduler started with 6 jobs; 0 `job.failure` audit events |
| Real Redis/BullMQ listener | NOT_RUN (not installed) |

Review: SELF_REVIEW only; independent review NOT_RUN.
