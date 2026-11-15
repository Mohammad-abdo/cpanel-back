# TASK-007 test evidence (partial)

Date: 2026-11-15. Local, mocked Prisma. `npx vitest run` in apps/api: 8 files, 39 tests PASS.

| Check | Result |
| --- | --- |
| Audit redaction of secret-looking keys (recursive) | PASS |
| occurredAt defaults to now; payload stored redacted | PASS |
| Denied grant attempt audited | PASS |
| Team create audited | PASS |
| Append-only / independent tamper-resistant replication | NOT_RUN (design only; Prisma alone cannot guarantee it) |
| ActivityEvent aggregates, access reviews | NOT_RUN |
| Production | NOT_RUN |
