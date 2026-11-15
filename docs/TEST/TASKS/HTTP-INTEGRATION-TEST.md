# HTTP Integration Test Record

Scope: HTTP-level integration tests for apps/api using Supertest against the real Express app (`createApp()`), with Prisma replaced by an in-memory fake (`tests/http/fake-prisma.js`, built on `tests/phase3-helpers.js`). No MySQL, no network, no production access. This is local test evidence only, not production verification.

## Files

- apps/api/tests/http/fake-prisma.js (shared fake + seed helpers)
- apps/api/tests/http/core.http.test.js (100 tests): health, helmet, 404 envelope, malformed JSON, 64kb limit (413), 500 envelope without leaks, 401 table over every GET route discovered from src/routes.js mounts, strict-schema unknown keys, invalid UUID params
- apps/api/tests/http/auth.http.test.js (21 tests): login success/failure/validation, 429 with Retry-After, MFA pending flow and enroll/confirm bypass fix, logout, expired/revoked 401, disabled 403, sessions scoping, password change policy and rate limit
- apps/api/tests/http/domain.http.test.js (15 tests): agents enroll/report/revoke, servers Owner-only create and scope 404, teams scoping, notification user scoping, audit read grants, approval separation of duties, project scope 404

## Dependency

supertest ^7.3.2 (devDependency of @nodeteam/api; already present in package.json at the time of this task).

## Command and result

`cd apps/api && npx vitest run` — 39 files, 485 tests passed (136 new in tests/http).

## Bugs found

None. Every asserted behavior matched the implementation; no `it.fails` or skipped tests were needed.

## Notes and limits

- The fake supports equality/comparison/OR/AND operators, compound-unique selectors, `select`, and the includes needed by session, audit and team scoping. Other includes are ignored, so service code relying on nested relations is not exercised.
- Rate limiter state is per-process in memory; each test file gets a fresh module instance and uses distinct emails/sessions.
- Real MySQL behavior (constraints, transactions, cursor pagination) is not covered here.
