# TASK-012 test evidence

Date: 2026-11-15. Scope: Scoped log search, live stream and export. Environment: local Windows workspace, Vitest with an in-memory Prisma double and the in-memory log store.

| Check | Command | Result |
| --- | --- | --- |
| Observability unit tests | `cd apps/api && npx vitest run tests/phase4-observability.test.js` | 17 passed, 0 failed |
| Peer slice tests | `npx vitest run tests/phase4-logs.test.js` | 4 passed, 0 failed |
| Router modules import cleanly | `node -e` dynamic import of logs, monitoring and alerts routes | ok |

Covered: filters (level, request id, trace id, deployment id, text, time), cross-project/wrong-environment/environment-less denial, CSV formula neutralization and audited export, SSE subscription tenancy at subscribe and per event, Last-Event-ID reconnect replay, bounded-queue backpressure with a dropped notice, per-user bookmarks.

## NOT_RUN

- Socket.IO transport: not implemented. SSE is used because Socket.IO is not a dependency (REQUIRES DECISION).
- Real network backpressure on a socket and proxy buffering: NOT_RUN.
- Live HTTP/SSE against a database and a real browser EventSource: NOT_RUN. Production verification: not claimed.
