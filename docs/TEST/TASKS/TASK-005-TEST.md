# TASK-005 test evidence

Date: 2026-11-15. Environment: local Windows, no Docker/MySQL runtime.

| Check | Method | Result |
| --- | --- | --- |
| TOTP generate/verify | `tests/totp.test.js` | PASS |
| Invalid credentials | `tests/auth.service.test.js` | PASS |
| MFA-pending session on login | mocked Prisma | PASS |
| Valid/invalid TOTP verify | mocked Prisma | PASS |
| Owner escalation denied | `tests/users.service.test.js` | PASS |
| Owner self-demotion blocked | mocked Prisma | PASS |
| Full suite | `npm test` | PASS — 22 tests / 6 files |
| Live MySQL migrate + seed | Laragon MySQL via apps/api/.env | PASS — `20261115150000_init` + `auth_credentials`; Owner seeded |
| CSRF | — | NOT_RUN (session bearer model; cookie CSRF later if cookies added) |
| Production | — | NOT_RUN |

## Update 2026-11-15 — scrypt password hashing
`tests/rbac-teams.test.js`: scrypt verify/reject/unique salt and legacy SHA-256 compatibility PASS. Full suite 35 tests PASS.
