# Release acceptance matrix (TASK-031)

Status: DRAFT, updated 2026-11-15. Acceptance is NOT claimed. A row is PASSED only when a recorded test or review proves it. Local tests are not production verification.

Legend: LOCAL = automated tests and live checks against the local API, local MySQL and the local SSH test server passed. SIMULATED = the server-side action used a simulated adapter (no real Nginx, DNS, ACME, MySQL admin, restic, ufw or Wazuh). NOT_RUN = no execution exists. UNKNOWN = no evidence or no decision.

## Evidence commands (all in cpanel-back, API running, demo data seeded)

| Command | What it proves | Last result |
| --- | --- | --- |
| `npx vitest run` (from a `C:\` path) | Unit and integration tests, incl. real SSH/SFTP protocol tests | 40 files, 534 tests PASS |
| `npm run seed:demo` | Every main flow through the real API, incl. approvals | 25/25 on a fresh database |
| `npm run smoke` | Every GET route; anonymous/non-owner/approval boundaries | 71 GET 2xx, 0 5xx; 12/12 |
| `npm run drill:security` | Incident lifecycle, firewall with approval, access review | 30/30 |
| `npm run test:security` | IDOR, escalation, sessions, mass assignment, CSRF/CORS, headers, errors, rate limit, terminal tickets | 43/43 |
| `npm run test:load` | 25 users x 20 s on 12 read endpoints | 564 req/s, p95 72 ms, 0 errors (budget p95 <= 500 ms) |
| `npm run drill:recovery` | Panel database backup and restore into a copy, row counts compared | PASS: backup 0.6 s, restore 3.9 s, 65 tables, 0 mismatches |
| `vite build` (cpanel-admin) | Web app compiles | PASS |

## Matrix

| Area | Evidence | Status |
| --- | --- | --- |
| Sessions, MFA, Owner protection, RBAC (TASK-005..007) | unit tests; test:security sessions/escalation | LOCAL; independent review NOT_RUN |
| Agents, metrics, servers (TASK-008..010) | unit tests; seed agents | LOCAL; Go agent not compiled, mTLS NOT_RUN |
| Operations, projects, deployments, rollback (TASK-017..019) | unit tests; seed | LOCAL + SIMULATED executors |
| Logs, errors, alerts (TASK-011..013) | unit tests; seed; scheduler | LOCAL; Loki NOT_RUN |
| Team timeline, reports (TASK-014..016) | unit tests; seed | LOCAL; PDF/Excel REQUIRES DECISION |
| Domains, SSL, databases (TASK-020..022) | unit tests; seed with approvals | LOCAL + SIMULATED |
| Backups, offsite, restore (TASK-023..025) | unit tests; live backup/verify/restore incl. after API restart | LOCAL + SIMULATED; real restic and offsite NOT_RUN |
| Wazuh, incidents, firewall, access reviews (TASK-026..028) | unit tests; drill:security 30/30 | LOCAL + SIMULATED; real Wazuh/ufw lockout test NOT_RUN |
| Multi-VPS scale and resilience (TASK-029) | test:load (single API process, one MySQL) | LOCAL; multi-VPS, outage/reconnect on real hosts NOT_RUN |
| Security testing, recovery, emergency Owner (TASK-030) | test:security 43/43; drill:recovery PASS; break-glass unit tests | LOCAL; external penetration test NOT_RUN; offsite control-plane restore NOT_RUN |
| SSH servers, file manager, terminal (TASK-035/036) | real SSH protocol tests; live API + WebSocket checks | LOCAL against test SSH server; real VPS NOT_RUN |
| Environment variables, project types (TASK-037) | unit tests; live 14 checks incl. .env written over SFTP | LOCAL |
| Server details page, home, shortcuts (TASK-033/038/039) | build; translation audit (1,160+ keys EN/AR, 0 missing) | LOCAL; browser click-through NOT_RUN |
| Independent review of all tasks | SELF_REVIEW only | NOT_RUN |
| Runbook rehearsal on a staging VPS | runbook written with commands | NOT_RUN |
| Production verification | none | NOT_RUN |
| Owner sign-off | none | NOT_RUN |

## Security test findings fixed in this pass
- A user without approval rights got "approval is not pending" instead of 403 (reveals existence/state). Permission is now checked first.
- The platform approvals list also returned deployment approvals (upper-case `PENDING` matched `pending` under MySQL's case-insensitive collation) and those could not be decided there. The list and decisions are now limited to platform approvals.

## Decisions still needed from the Owner
- Approved RPO and RTO per project (the recovery drill gives a measured local restore time to start from).
- Approver model for a single-Owner install: today a second user holding `platform.approval.decide` is required.
- Offsite backup target, credential separation and immutability.
- DNS provider and ACME client.
- Firewall maintenance windows; access review cadence (default 90 days in `NT_ACCESS_REVIEW_DAYS`).

## Closure rule
TASK-031 stays open until every row has recorded evidence on real infrastructure where required, an independent review passes, and the Owner signs off.
