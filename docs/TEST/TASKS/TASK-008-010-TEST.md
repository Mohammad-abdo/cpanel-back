# TASK-008 / 009 / 010 test evidence (partial)

Date: 2026-11-15. Local. `npx vitest run` in apps/api: 9 files, 51 tests PASS (mocked Prisma). `vite build` OK.
Migration `agent_enrollment` applied to the local Laragon dev database (additive only).

| Check | Result |
| --- | --- |
| Enrollment token: unknown/used/expired rejected; concurrent claim rejected; key shown once, only hash stored | PASS |
| Agent auth: wrong key, revoked, unknown agent, malformed header rejected | PASS |
| Report validation (range, unknown keys); snapshot + services + ports stored; status derived | PASS |
| Server registration and enrollment issue are Owner-only; credentials never returned in server lists | PASS |
| Silent agent shown offline (3 min), no agent shown unknown | PASS |
| Fleet averages bucketed | PASS |
| Live API end-to-end (register, token, enroll, 3 reports, servers/metrics/fleet read-back; bad/absent credentials rejected) | PASS on 2026-11-15 against live API + Laragon MySQL via curl and dev-agent. Browser UI click-through NOT_RUN |
| mTLS (certificates, CA, pinning) | NOT_RUN / REQUIRES DECISION: interim key credential in use, not mTLS |
| Go agent build and Ubuntu discovery of real processes/ports | NOT_RUN: Go toolchain absent; `scripts/dev-agent.mjs` is a dev harness only |
| Reconnect replay protection, per-server permission scoping | NOT_RUN |
| Production | NOT_RUN |
