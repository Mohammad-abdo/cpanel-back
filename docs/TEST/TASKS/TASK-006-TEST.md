# TASK-006 test evidence

Date: 2026-11-15. Environment: local Windows, mocked Prisma (no live DB for these checks).
Command: `npx vitest run` in apps/api. Result: 7 files, 35 tests PASS.

| Check | Result |
| --- | --- |
| Non-owner granting a permission they lack is denied (SCOPE_EXPANSION_DENIED) | PASS |
| Self-grant denied | PASS |
| Environment required for project.* permissions | PASS |
| Delegate may re-grant only held + assignable scope | PASS |
| hasGrant: no match without environment; query pinned to exact environment (staging != production) | PASS |
| Revoke limited to Owner or original grantor | PASS |
| Only Owner creates teams; non-members cannot manage; lead cannot appoint/remove leads | PASS |
| Cross-project isolation against live data | NOT_RUN |
| Route-level (HTTP) tests for /teams and /rbac | NOT_RUN |
| Production | NOT_RUN |
