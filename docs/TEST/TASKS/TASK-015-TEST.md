# TASK-015 test evidence

Date: 2026-11-15. Scope: Team and project reports with event lineage. Environment: local Windows workspace, Vitest with an in-memory Prisma double.

| Check | Command | Result |
| --- | --- | --- |
| Reports tests | `cd apps/api && npx vitest run tests/phase5-reports.test.js` | 18 passed, 0 failed (shared with TASK-016) |
| Combined phase 03-05 run | `npx vitest run` on the six phase3/4/5 files | 84 passed, 0 failed |
| Router modules import cleanly | `node -e` dynamic import of the routes files | ok |

Covered: fixture aggregates recomputed by hand, lineage ids equal the source rows, half-open period boundaries, N/A for zero denominators, retries and duplicate rows counted once, individual report initiator versus approver, contribution/changes/security/workload/access reports, scoped authorization on report.team.export and self-only individual reports, period validation.

## UI lineage slice (2026-11-15 evening)

| Check | Result |
| --- | --- |
| Reports page metric/breakdown **Open lineage** modal | Implemented; shows capped `lineage[]` with source + id + link to origin list |
| Live `GET /reports/preview` (Owner, demo project) | 200; 10 metrics; first metric `deployments.total` lineageTotal=1 |
| Artifact download buttons after run | Wired to `GET /reports/artifacts/:id/download` (blob) |

## NOT_RUN

- Uptime, latency, request-rate, slow-query and backup-verification sections of required.md section 6: NOT_RUN and not implemented (their data sources are Prometheus, database and backup modules owned elsewhere).
- Full browser click-through of lineage + download: NOT_RUN in this pass.
- Production verification: not claimed.
