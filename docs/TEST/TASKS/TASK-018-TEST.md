# TASK-018 test evidence

Date: 2026-11-15. Scope: Project discovery, Git, runtime and lifecycle. Environment: local Windows workspace, Vitest with an in-memory Prisma double.

| Check | Command | Result |
| --- | --- | --- |
| Projects, deployments and operations unit tests | `cd apps/api && npx vitest run tests/phase3-projects-deployments.test.js tests/phase3-operations.test.js` | 38 passed, 0 failed (21 in projects/deployments file) |
| Router modules import cleanly | `node -e` dynamic import of the three routes files | ok |

Covered: read-only discovery (no deployment, no existing-project mutation, no operations created), Owner-only create/configure/archive, duplicate slug, secret names only (values rejected, metadata redacted), git credential stripping, member-only visibility, PM2 lifecycle through the operation queue with exact environment scope and idempotent replay, shared-service impact preview, archive blocked during active deployment, production-escalated deployments needing a separate approver, build failure (no rollback), step records with timing and redaction.

## NOT_RUN

- Agent-side git pull, build, pm2 reload and rollback on a real server: NOT_RUN (runner and health checker are simulated ports).
- Live HTTP and database integration: NOT_RUN. Production verification: not claimed.
- No automated discovery agent exists; discovery accepts agent-reported candidates (UNKNOWN until the Agent reports them).
