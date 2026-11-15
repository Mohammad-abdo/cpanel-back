# TASK-011 test evidence

Date: 2026-11-15. Scope: Log ingestion and redaction. Environment: local Windows workspace, Vitest with an in-memory Prisma double and the in-memory log store.

| Check | Command | Result |
| --- | --- | --- |
| Observability unit tests | `cd apps/api && npx vitest run tests/phase4-observability.test.js` | 17 passed, 0 failed |
| Peer slice tests | `npx vitest run tests/phase4-logs.test.js` | 4 passed, 0 failed |
| Router modules import cleanly | `node -e` dynamic import of logs, monitoring and alerts routes | ok |

Covered: redaction of bearer tokens, passwords, JWTs, credential URLs, API keys, cookies and private keys before storage and again on display; project/server/environment labels derived from the registered source (gateway-controlled); agent bound to another server rejected and audited; non-Owner user ingest rejected; foreign deploymentId entries rejected; injected error reaches only the correct project and error group; Owner-only source registration with environment/project match.

## NOT_RUN

- Agent-side shipping of PM2/Apache/Nginx/database/job logs and the Agent's HTTP ingest call: NOT_RUN (UNKNOWN until the Agent exists).
- Live HTTP/SSE against a database and a real browser EventSource: NOT_RUN. Production verification: not claimed.
