# TASK-013 test evidence

Date: 2026-11-15. Scope: Error groups, alert lifecycle and deployment comparison. Environment: local Windows workspace, Vitest with an in-memory Prisma double and the in-memory log store.

| Check | Command | Result |
| --- | --- | --- |
| Observability unit tests | `cd apps/api && npx vitest run tests/phase4-observability.test.js` | 17 passed, 0 failed (re-run same day after mounting alerts router) |
| Peer slice tests | `npx vitest run tests/phase4-logs.test.js` | 4 passed, 0 failed |
| Combined phase4 files | `npx vitest run tests/phase4-observability.test.js tests/phase4-logs.test.js` | 21 passed, 0 failed |
| Router modules import cleanly | `node -e` dynamic import of `monitoring.routes.js` (includes alertsRouter) | ok |
| Web build | `npm run build:web` | ok (Alerts page + EN/AR strings) |

Covered: repeated-error threshold with dedup, auto-resolve and reopen; intermittent threshold across buckets (a single burst does not fire); no-data only when a log source exists, otherwise unknown; acknowledge, escalate and manual resolve with audit and scope checks; Owner-only rules; deployment before/after comparison without developer attribution. Dashboard: `/monitoring` lists alerts/rules, Owner create rule, evaluate, ack/resolve, deploy error comparison with attribution note.

## Fix this pass

- `alertsRouter` was implemented but not mounted on `monitoringRouter`; now mounted via `monitoringRouter.use(alertsRouter)`.

## NOT_RUN

- Notification delivery (email/Telegram) of escalations: NOT_RUN; only an in-app Notification row for Owners is created.
- A scheduler that calls `evaluateAll` and `escalateDue`: NOT_RUN (worker hook still absent).
- Live HTTP/SSE against a database and a real browser EventSource: NOT_RUN. Production verification: not claimed.
