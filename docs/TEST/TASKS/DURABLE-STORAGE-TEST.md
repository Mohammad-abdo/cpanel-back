# Durable storage test record

Scope: Prisma-backed LogEntry store and filesystem report artifact store.

## Commands and results

| Command (cwd apps/api) | Result |
| --- | --- |
| `npx prisma validate` | PASS (schema valid) |
| `npx prisma migrate dev --create-only --name log_entries --skip-generate` | Created `20261115165113_log_entries`; SQL reviewed: only CREATE TABLE and indexes, no DROP/DELETE |
| `npx vitest run` | PASS: 27 files, 278 tests (includes `tests/storage-durable.test.js`) |

## Covered (mock based)

- Redaction applied before persistence; project-scoped durable query; retention pruning; SCHEMA_REQUIRED (501) when the LogEntry delegate is missing.
- File artifact store: round trip, traversal-style refs hashed to safe filenames, size limit, checksum, expiry pruning.

## NOT_RUN

- Migration apply and `prisma generate`: NOT_RUN (lead applies).
- Real MySQL integration of LogEntry store: NOT_RUN.
- Running API end to end with durable stores: NOT_RUN.
- No production verification is claimed.
