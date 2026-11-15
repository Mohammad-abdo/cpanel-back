# TASK-004 test evidence

Date: 2026-11-15. Environment: local Windows workspace.

| Check | Command / method | Result |
| --- | --- | --- |
| Prisma validate | `npm run prisma:validate` with `DATABASE_URL` set | PASS — schema valid |
| Prisma generate | `npm run prisma:generate` | PASS — client generated |
| API unit/integration | `npm test` | PASS — 12 tests / 3 files |
| Web build | `npm run build:web` | PASS — Vite production build |
| MySQL migrate against running DB | docker compose + migrate | NOT_RUN — compose file present, services not started this pass |
| Worker Redis connection smoke | start worker with Redis | NOT_RUN |
| Production | — | NOT_RUN |

Notes: Prisma CLI currently pulls `deepmerge-ts` advisory via `@prisma/config` (dev tooling). Do not treat local passes as production verification.
