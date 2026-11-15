# TASK-019 test evidence

Date: 2026-11-15. Scope: Deployment health checks and rollback. Environment: local Windows workspace, Vitest with an in-memory Prisma double.

| Check | Command | Result |
| --- | --- | --- |
| Projects, deployments and operations unit tests | `cd apps/api && npx vitest run tests/phase3-projects-deployments.test.js tests/phase3-operations.test.js` | 38 passed, 0 failed (21 in projects/deployments file) |
| Router modules import cleanly | `node -e` dynamic import of the three routes files | ok |

Covered: health success verified, health failure never reports Success (auto rollback to previous good release or Failed), health timeout as failure, shared-service impact recorded on failure, manual rollback approval-gated with target validation (same project and environment, previous Success), source marked Rolled Back, idempotent create and no re-run of a finished deployment.

## NOT_RUN

- Agent-side git pull, build, pm2 reload and rollback on a real server: NOT_RUN (runner and health checker are simulated ports).
- Live HTTP and database integration: NOT_RUN. Production verification: not claimed.
- No automated discovery agent exists; discovery accepts agent-reported candidates (UNKNOWN until the Agent reports them).
