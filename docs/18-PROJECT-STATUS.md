# Project status

2026-11-15. Current phase: 06 Domains — TASK-020 UI manage (vhost/DNS) in progress after TASK-015/016 local slices; nothing DONE.

## Registry (honest)

| Bucket | Count / note |
| --- | --- |
| Total tasks | 32 |
| DONE | 0 (independent review gates still open) |
| Local implementation advanced | TASK-001…010 / 017 areas scaffolded |
| Production verification | NOT_RUN |
| Completed progress claim | Do not treat scaffolds as production-ready |

## What landed locally this pass

- Prisma MySQL schema covering Identity, AuthZ, Teams, Infra, Projects, Deployments, Operations, Hosting, Backups, Monitoring, Logs metadata, Security, Reports, Audit, Notifications
- Workspaces: `apps/api`, `apps/web`, `apps/worker`, shared packages, `agents/ubuntu-agent` scaffold
- Phase 00 design (TASK-001/002/003): IN_REVIEW — contracts, design system, UI screens; independent review pending
- API modules (controller/validator/service/routes): health, auth, audit, rbac, operations, servers, projects, monitoring, deployments, backups, domains, logs, security, reports
- Session middleware fail-closed; protected routes require Bearer session
- Web shell: MUI 9 + Tailwind 4 + Motion Overview + 6 sidebar groups
- Worker BullMQ operations queue listener; Go agent envelope validation scaffold
- Local evidence: Vitest 22 passed; Laragon MySQL migrations applied; Owner seeded
- Database: Laragon MySQL `nodeteam_control` via `apps/api/.env` (no Docker)

## Still open / UNKNOWN

- Production Ubuntu inventory, security baseline
- RPO/RTO and offsite decisions
- MFA TOTP + Owner protection implemented; independent review pending
- Change seeded Owner password before any shared use
- Independent reviews for task DONE gates
- Full Agent mTLS, Loki/Prometheus, restore drills, multi-VPS

Owner authorized continuing phases with UNKNOWN markers; this does **not** authorize production deploy, firewall, secret rotation, or restore.

## Update — password hashing, RBAC, teams

- Password hashing upgraded from SHA-256 to salted scrypt (`common/crypto/password.js`); legacy hashes verify and upgrade on login. Closes the TASK-005 self-review note.
- TASK-006: RBAC scope-expansion/self-grant/environment-strict checks, grant revoke, `teams` module. Vitest: 35 passed. See TEST/TASKS/TASK-006-TEST.md. Independent review pending; production NOT_RUN.

## Update — dashboard redesign and audit wiring

- Web: dark graphite redesign (one teal accent, IBM Plex, status-dot signature), full 6-group sidebar from required.md section 12, responsive drawer, Overview with fleet-load chart, servers, deployments, activity. Data is sample only; `vite build` OK. Not browser-verified in this pass.
- TASK-007 (in progress): audit redaction and grant/team audit hooks. Vitest 39 passed. Production NOT_RUN.

## Update — dashboard connected to API

- Web now has sign-in (password + TOTP step), session store, axios client, route guard and sign-out. Overview reads `/servers`, `/projects`, `/deployments`, `/audit/events`; sample data removed.
- Evidence (local, live API + Laragon MySQL): `POST /auth/login` 200 for the seeded Owner; the four list endpoints return 200 with the shapes the UI reads; `vite build` OK. Lists are empty (no servers/projects registered). Browser walkthrough NOT_RUN.
- Gap: no create endpoints for servers/projects yet (TASK-008/018 scope), so the UI cannot register them. Fleet-load chart shows an empty state until agents report metrics (TASK-009/010).

## Update — servers, agents, metrics (TASK-008/009/010 in progress)

- API: `POST /servers`, `POST /servers/:id/enrollment`, `POST /agents/enroll`, `POST /agents/report`, `DELETE /agents/:id`, `GET /servers/:id/metrics`, `GET /monitoring/fleet`. New `agents` module. Prisma model `AgentEnrollment` + migration.
- Web: Servers page (register, enrollment command, live status), Overview fleet chart from stored snapshots.
- Dev harness: `npm run dev:agent` (enroll/run) reports this machine's metrics. Not the production agent; interim key credential, not mTLS.
- Vitest 51 passed. Live end-to-end NOT_RUN (API restart needed). Production NOT_RUN.

## Update — Phase 04 logs / errors (TASK-011/012/013 in progress)

- Restored missing `monitoring.errors.js` (API routes import again).
- Logs gateway: ingest (agent/manual), search, export, SSE stream, bookmarks; redaction before store/display.
- Error groups from error/fatal ingest; `GET /monitoring/errors`.
- Web: `/logs` and `/errors` pages connected to API (project-scoped search + inject test line).
- Evidence: Vitest **156** passed; `vite build` OK. Loki production store still REQUIRES DECISION (in-memory default). Browser walkthrough NOT_RUN.

## Update — TASK-013 alerts UI + mount fix

- Mounted `alertsRouter` on `monitoringRouter` (rules, alerts ack/resolve, deploy error comparison were previously unreachable over HTTP).
- Web: `/monitoring` Alerts page (project filter, rules, Owner create rule, evaluate, ack/resolve, deploy comparison with no-blame note); EN/AR strings; Rubik already in use.
- Also routed existing module pages (projects, deployments, domains, SSL, databases, backups, security, incidents, reports, approvals, member timeline) that previously fell through to the placeholder.
- Evidence: phase4 Vitest **21** passed; `monitoring.routes` import ok; `vite build` OK. Escalate scheduler and live browser NOT_RUN. Independent review pending; not DONE.
- Next in phase order was Phase 05 TASK-014 (started below).

## Update — TASK-014 team timeline UI (in progress)

- `GET /users` list: Owner sees directory; non-owners see self only (no password fields).
- Web: `/team` member directory; `/team/:userId` profile summary + timeline (initiator/approver/executor roles, attribution, source links); Owner identity-mapping panel for unattributed SSH/Git with map-to-member form.
- EN/AR strings for team/member screens. ExternalIdentity table already in Prisma/migration (store no longer SCHEMA_REQUIRED when client is generated).
- Evidence: `phase5-members` Vitest **7** passed; `vite build` OK. Live browser + real SSH/Git collectors NOT_RUN. Independent review pending; not DONE.
- Next: TASK-015 reports lineage UI polish / TASK-016 schedules if 014 local slice is accepted for advance.

## Update — phases 03 to 09 implemented locally (nothing DONE)

Two parallel agents implemented TASK-011..031 in plan order against simulated adapters; the lead merged them.

- Code: modules for operations/approvals, projects/deployments/rollback, logs, error groups/alerts, members/activity, reports (CSV), domains, certificates, databases, backups, restores, security, incidents, firewall, access-reviews, platform (approval gate, AES-256-GCM helpers, fleet, break-glass). All routers mounted in `apps/api/src/routes.js`; pages wired in `apps/web/src/app/App.jsx`.
- Schema: additive migration `phase3_9_additive` (nullable columns + `ExternalIdentity`) applied to the local dev DB; no destructive statements. Prisma client regeneration is pending an API restart.
- Evidence: Vitest 24 files / 257 tests PASS (mocked Prisma); `vite build` OK; live smoke of GET routes on the running API returned 200/400/404 with no 500 (404 = router has no root listing).
- Registry: TASK-007..031 are IN_PROGRESS. None is DONE: no independent review, and real execution is NOT_RUN.

## Honest gaps (REQUIRES DECISION / NOT_RUN)

- Real execution: git/pm2/rollback, certbot, DNS provider, MySQL admin, restic/mysqldump, ufw, Wazuh, fleet probes. Defaults are simulated (the simulated health checker reports healthy).
- Dependencies not installed: BullMQ (queue is the persisted OperationJob status), Socket.IO (live logs use SSE), PDF/Excel renderers (501 FORMAT_REQUIRES_DECISION).
- Storage: log store and report artifacts are in memory by default (lost on restart); Loki/MySQL choice open.
- No worker wiring for scheduled jobs (expiry scan, retention, backup schedules, report runs, alert evaluation).
- mTLS not implemented (interim agent key); Go agent not built (no Go toolchain here).
- Approvals need a second user with approve rights; new permissions (`platform.approval.decide`, `project.database.manage`, `security.incident.manage`, `platform.access.review`, `operation.approve`, `project.configure`) are not yet in the permission catalog, so only the Owner passes those checks.
- Env vars required: BACKUP_ENCRYPTION_KEY (fails closed if absent), EMERGENCY_RECOVERY_CODE_SHA256.
- Unknown: approved RPO/RTO, offsite destination and immutability, approver model, production inventory.
- Web pages from phases 03-09 use plain English strings (Arabic localization pending); browser click-through NOT_RUN.

## Update — hardening, storage, scheduler, roles, UI (nothing DONE)

- Security: MFA-bypass, rate limiting, audit-read permission, atomic approval consume fixed; project-scope checks added to list/get in servers, monitoring, backups, restores, domains, databases, certificates, incidents, security; firewall approval binding includes the maintenance window; backup retention env check. Evidence: Vitest 29 files / 292 tests PASS (mocked Prisma). This is AI review remediation, not the human independent review (see docs/REVIEW/TASKS/AGENT-SECURITY-*.md). Open: fail-open with no actor in deployments/logs/projects; environment-scoped roles do not grant project visibility.
- Roles: 8 roles + 6 new permission keys + role evaluation in rbac.can; seed support written, seed NOT yet run.
- Storage: `LogEntry` migration `20261115165113_log_entries` applied to the local dev DB; file-backed report artifact store (`.data/artifacts`). Prisma client regeneration pending an API restart.
- Worker: dependency-free scheduler (`npm run start:scheduler --workspace @nodeteam/worker`), 7 jobs, 7 tests; not run against live MySQL.
- UI: full-width modern shell, shared components, every page wired to its API with create/action flows; 472 i18n keys in en/ar; `vite build` OK; browser check NOT_RUN. Demo data via `npm run seed:demo` (dev only, `demo-` prefix).
- Dev env: a local-only BACKUP_ENCRYPTION_KEY was added to the gitignored apps/api/.env.
- Known gaps: no API to register a database instance or create a report definition; seed-created certificates are re-issued on each run (GET /certificates empty before client regeneration); simulated executors produce no failed deployments.

## Update — Go agent, OpenAPI, review packets, browser QA, fail-closed (nothing DONE)

- Evidence (2026-11-15): Vitest 30 files / 300 tests PASS (mocked Prisma); `vite build` OK; OpenAPI regenerated (145 operations, 120 schemas); live API smoke: login OK and servers/projects/deployments/domains/certificates/databases/backups/incidents/reports/teams/audit/fleet all 200 with demo data; real-browser QA of all routes at 1920/1280/390 with no console errors or 4xx/5xx (see docs/TEST/TASKS/UI-BROWSER-QA.md).
- New: Go agent source in `agents/ubuntu-agent` (compile and tests NOT_RUN: Go not installed); `docs/openapi.json` (`npm run openapi`); 31 independent-review packets in `docs/REVIEW/PACKETS/` (reviewer fields blank; no task reviewed or DONE); fail-closed reads in projects/deployments/logs; `POST /databases/instances`, `POST|GET /reports/definitions` with web forms.
- Open: DatabaseInstance lacks host/port/secret-ref columns and ReportDefinition lacks kind/project columns (needs additive migration); placeholder pages remain for my-activity, notifications, services, network, storage, runtime, team-analytics, audit, integrations, settings; report type names, cron text and raw audit action codes are not translated in Arabic; Go agent must be compiled and tested on a machine with Go and run on a real Ubuntu host; certificate list returned empty although certificates were issued (investigate); no human independent review; real executors, mTLS, queue/PDF/Excel dependencies and production verification remain NOT_RUN / REQUIRES DECISION.

## Update — approvals null-job fix + TASK-020 domains UI (nothing DONE)

- Bugfix: Approvals Review called `GET /operations/null/impact` when `operationJobId` was null (orphaned seed rows). UI now uses stored `impactJson`, skips the impact request, and disables decide/execute without a linked job.
- TASK-020: Domains **Manage** modal — vhost preview/apply + DNS change against existing API; Vitest phase6-domains **16** passed. Real Apache/DNS still simulated. Independent review pending; not DONE.
- Next: TASK-021 SSL polish or remaining TASK-020 browser QA.

## Update — TASK-015/016 reports UI completion slice (nothing DONE)

- Web `/reports`: event lineage modal (metric/breakdown → capped source refs + origin links); artifact download after run; **New schedule** modal (weekly/monthly cron presets, recipients from `/users`, csv/json only — PDF/Excel remain REQUIRES DECISION).
- API already had preview lineage + schedules + worker `reports.runDue`; UI was the missing piece.
- Evidence: Vitest `phase5-reports` **18** passed; live login + preview returned metrics with lineage. Browser click-through of new controls NOT_RUN. Independent review pending; not DONE.
- Next in phase order after 015/016 local acceptance: Phase 06 TASK-020 domains/DNS polish (or close remaining 015/016 NOT_RUN items first).

## Update — project detail page, account and infrastructure pages, schema columns (nothing DONE)

- New web pages: `/projects/:projectId` (13 tabs, header + KPI strip, env switcher, ?tab/?env URL state), notifications, my activity, audit (filters, drawer, CSV), settings (password change, TOTP enrol, sessions), services, network, storage, runtime, team analytics, integrations. Remaining placeholder routes: none of the sidebar items are placeholders any more except any not listed here (verify in the browser).
- New API: notifications module; `/auth/password/change`, `/auth/sessions`, `/auth/me`; `/activity/me`; audit filters; `/projects/:id/overview|members`; `/servers/services|ports|runtimes`; `/firewall/history`; `/members/analytics`; `/platform/integrations`.
- Schema: additive migration `20261115171615_instance_and_report_columns` (6 nullable columns) applied to the local dev DB; services fall back with `schemaPending` on a stale Prisma client.
- Evidence (2026-11-15): Vitest 35 files / 337 tests PASS (mocked Prisma); `vite build` OK; OpenAPI regenerated (163 operations, 131 schemas); live API: certificates/instances/services/ports/integrations/notifications 200; `npm run seed:demo` created 9, failed 0 (certificates and DNS issued through the real approval flow with demo-approver; demo database instance registered). Browser checks: project detail 13 tabs at 1280 and Arabic narrow; six infrastructure pages once each; account pages NOT_RUN in the browser. See docs/TEST/TASKS/{PROJECT-DETAIL,ACCOUNT-PAGES,INFRA-PAGES,SCHEMA-COLUMNS}-TEST.md.
- Root cause of empty certificates: High-risk actions return 202 approvalRequired and create nothing until a second user approves; the old seed treated 202 as success. Seed now follows the approval flow.
- Open: project detail not checked at 1920 or exactly 390 px, 404 state, any write action, keyboard walk-through, non-Owner view; logs tab needed the regenerated client (LogEntry); Team tab shows project members only (no team-to-project link in the API); email notification channel absent; Arabic of infra pages verified by key parity only; no human independent review; real executors, mTLS, queue/PDF/Excel dependencies, Go agent compile, and production verification remain NOT_RUN / REQUIRES DECISION.
