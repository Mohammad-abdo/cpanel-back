# TASK-001 — Inventory and discovery

Date: 2026-11-15. Status: IN_REVIEW (deliverables complete with UNKNOWN production inventory; independent review pending).

Evidence scope: local file enumeration and toolchain checks on `D:/SERVER-CPANEL`. No remote Ubuntu access performed. No secrets collected.

## Owner authorization (2026-11-15)

User explicitly authorized continuing through **all phases** with production inventory left as **UNKNOWN**. This authorization:

- Allows Phase 00 design work (TASK-002, TASK-003) and subsequent phases to proceed without waiting for filled production host rows.
- Does **not** invent production facts, host lists, versions, or baseline values.
- Does **not** mark production inventory checks, security baseline evidence, or RPO/RTO decisions as PASSED.
- Does **not** waive independent review before DONE.
- Does **not** authorize production deployment, firewall changes, secret rotation, or destructive operations.

Production worksheets remain UNKNOWN / REQUIRES DECISION until Owner supplies evidence or decisions.

## Verified local state

| Item | Evidence |
| --- | --- |
| Workspace | `D:/SERVER-CPANEL` on Windows development host |
| Toolchain | Node `v24.18.0`, npm `11.16.0` (shell check 2026-11-15) |
| Root package | npm workspaces: `apps/api`, `apps/web`, `apps/worker`, shared packages |
| API stack present | Express, Helmet, Zod, Vitest, Supertest, Prisma client |
| API modules | health, auth, audit, rbac, operations, servers, projects, monitoring, deployments, backups, domains, logs, security, reports (each controller/validator/service/routes) |
| Prisma / MySQL | `apps/api/prisma/schema.prisma` present and `prisma validate` OK; migrations against live MySQL NOT_RUN |
| Web app | `apps/web` MUI 9 + Tailwind + Motion shell; local production build OK |
| Worker | `apps/worker` BullMQ operations queue scaffold |
| Go Agent | `agents/ubuntu-agent` envelope-validation scaffold (no mTLS bind in this slice) |
| Design contracts | TASK-001/002/003 deliverables IN_REVIEW (see docs/04–06, docs/design-system, docs/08-UI-SCREENS) |
| Historical tests | Vitest local evidence exists; not production verification |

## Production Ubuntu inventory

Status: UNKNOWN — no authorized read-only remote inventory yet. Owner authorized 2026-11-15 to leave this UNKNOWN while work continues.

Required per host (non-secret only):

- Alias / role (control-plane candidate vs app host vs shared DB/cache)
- Ubuntu version and patch window
- vCPU, RAM, disk capacity and free space
- Shared services and versions: Apache/Nginx, PM2, systemd units of interest, MySQL, PostgreSQL, MongoDB, Redis
- Listening ports categories (no credentials)
- Project count by runtime: Node/PM2, Laravel, WordPress, Static, Custom
- Domain and certificate ownership summary (names only)
- Backup destination category and last restore-test date if known

Do not record passwords, private keys, tokens, `.env` values, or DB connection strings.

Worksheet: [SERVER-INVENTORY.md](SERVER-INVENTORY.md)

## Security baseline

Status: UNKNOWN until evidence or authorized read-only collection. Proceed-with-UNKNOWN authorized 2026-11-15.

Checklist: [SECURITY-BASELINE.md](SECURITY-BASELINE.md)

## Recovery objectives

Status: REQUIRES DECISION. Proceed-with-UNKNOWN authorized 2026-11-15; Owner decisions still required before treating recovery gates as closed.

Worksheet: [RECOVERY-OBJECTIVES.md](RECOVERY-OBJECTIVES.md)

## Acceptance and remaining work

Local inventory recorded with evidence. Production inventory, security baseline, and recovery objectives remain UNKNOWN / REQUIRES DECISION by Owner authorization to continue.

TASK-001 deliverables for Phase 00 discovery documentation are complete under that authorization. Status: **IN_REVIEW**. Independent review pending. Do not mark DONE. Do not claim production tests PASSED.

No application feature code changes are in scope for this task.
