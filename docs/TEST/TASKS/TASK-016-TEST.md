# TASK-016 test evidence

Date: 2026-11-15. Scope: Scheduled report summaries and renderers. Environment: local Windows workspace, Vitest with an in-memory Prisma double.

| Check | Command | Result |
| --- | --- | --- |
| Reports tests | `cd apps/api && npx vitest run tests/phase5-reports.test.js` | 18 passed, 0 failed (shared with TASK-015) |
| Combined phase 03-05 run | `npx vitest run` on the six phase3/4/5 files | 84 passed, 0 failed |
| Router modules import cleanly | `node -e` dynamic import of the routes files | ok |

Covered: schedule creation with authorized recipients only, cron validation, idempotent per-period runs (retry deduplication), recipient re-validation at run time (revoked recipients skipped and audited), revoked recipient download rejected, expired artifact 410, no backfill, disabled schedules, CSV/JSON render parity and formula neutralization, PDF and Excel returning 501 REQUIRES DECISION.

## UI schedule slice (2026-11-15 evening)

| Check | Result |
| --- | --- |
| Reports page **New schedule** modal (weekly/monthly cron presets, recipients, csv/json) | Implemented; posts `POST /reports/schedules` |
| Worker job `reports.runDue` | Present in `apps/worker/src/jobs.js` (`NT_JOB_REPORTS_MS`, default 60s) |
| Live `POST /reports/schedules` (Owner → weekly csv) | 201; schedule created with cron `0 9 * * 1` |
| Vitest `tests/phase5-reports.test.js` | 18 passed |

## NOT_RUN

- PDF and Excel rendering: NOT_RUN and not implemented (REQUIRES DECISION, new dependencies). The renderer registry accepts a renderer with { format, contentType, extension, render(report) }.
- Email delivery: NOT_RUN. Recipients receive an in-app Notification only.
- Live worker process against MySQL running schedules end-to-end: NOT_RUN in this pass.
- Production verification: not claimed.
