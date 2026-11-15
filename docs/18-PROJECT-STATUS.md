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

## Update — repo split repair, demo seed, scheduler, phase 06 checks (nothing DONE)

2026-11-15. The monorepo was split into two standalone repos, `cpanel-back` (API) and `cpanel-admin` (web). There is no monorepo any more.

- `cpanel-back` standalone: the `@nodeteam/permission-catalog` and `@nodeteam/shared-contracts` workspace packages (sources not recoverable) were rebuilt as `src/common/permission-catalog.js` and `src/common/shared-contracts.js` from docs/07, docs/openapi.json and the tests. The risk tier per permission and the set of environment-scoped permissions are a reconstruction: REQUIRES REVIEW. `vite` added as a dev dependency (vitest 5 peer).
- Worker replaced by an in-process scheduler in the API (`src/jobs/`): operations expiry, alert evaluation and escalation, scheduled reports, SSL expiry scan (TASK-021 gap), backup retention plan (dry run). Disable with `NT_JOBS_ENABLED=false`; intervals via `NT_JOB_*_MS`. The Go agent is still absent from both repos.
- Bugs fixed: re-enrolling a server with an active agent returned 500 (now 409 `AGENT_ALREADY_ENROLLED`, token left unclaimed); `GET /backups/runs` returned 500 because `BackupArtifact.sizeBytes` is BigInt (app-wide JSON replacer).
- Demo data: `npm run seed:demo` in `cpanel-back` (rewritten; localhost only, `demo-` prefix, idempotent, real approval flow with `demo-approver`). Result: 24 steps, 0 failed; a second run creates nothing.
- Evidence: Vitest 38 files / 486 tests PASS (mocked Prisma); `npm run smoke` against the live API with demo data: 80 GET routes, 71 2xx, 0 5xx, 8 404 for routes with no seeded id, 1 SSE skipped; 12/12 auth-boundary checks PASS (anonymous 401, non-owner 403/404, high-risk 202 approval, self-approval 403). `cpanel-admin` `vite build` OK; all 72 API paths called by the UI match a backend route.
- Phase 06 live HTTP (TASK-020/021/022): domain create, vhost apply, DNS upsert, SSL issue, database instance, database and read-only user all executed through the live API with the approval flow (simulated adapters).
- Still NOT_RUN: browser click-through, real Apache/Nginx/DNS/ACME/MySQL execution, production verification, independent review.
- Note for Windows: run vitest from a path with an uppercase drive letter (`C:\...`); a lowercase `c:\` working directory loads vitest twice and every file fails with `Cannot read properties of undefined (reading 'config')`.

## Update — Phase 07 backup and recovery (TASK-023/024/025, nothing DONE)

- Scheduled backups: `backups.runDue` job (every 5 min) starts a backup when a policy is due by its frequency (hourly/daily/weekly), retries a failed run after 15 minutes, and isolates failures per policy. Runs as a dedicated system actor (`src/common/system-actor.js`; audit actorId null, trigger `scheduled`).
- Scheduled verification: `backups.verifyLatest` job (daily) re-reads the newest verified set of each policy from offsite storage; a checksum/decryption failure marks the run `verificationStatus=failed` and is audited.
- Restore: a failed health check after an in-place restore now restores the safety backup automatically (`rolledBack: true` in the audit and error); if that rollback fails, the error says to roll back manually with the safety backup id. Isolated restores never roll back.
- Bugs fixed: the simulated offsite store was in memory, so every API restart made all stored backups unreadable (verify/restore failed with CORRUPT_BACKUP); it now persists under `cpanel-back/.data/sim-offsite` (`NT_SIM_OFFSITE_DIR`). Report artifacts were written five levels up (outside the repo, to `Downloads/.data`) since the split; now `cpanel-back/.data/artifacts`. `.data/` is gitignored. Backup runs created before this fix in the local dev DB are unreadable and will fail validation if selected for restore.
- Demo seed adds an isolated restore drill approved by `demo-approver`.
- Evidence: Vitest 38 files / 495 tests PASS. Live (local MySQL): backup run retained+verified; after an API restart the artifact verified OK; isolated restore and in-place restore (with safety backup) completed through the approval flow. Fresh-database run on a temporary DB: seed 25/25 created, smoke 71 GET 2xx / 0 5xx, 12/12 boundary checks; the temporary DB was dropped.
- Still NOT_RUN / REQUIRES DECISION: real restic/mysqldump, real offsite target with separate credentials and object lock, measured RPO/RTO, real isolated scratch environment, independent review.

## Update — Phase 08 security and operations (TASK-026/027/028, nothing DONE)

- TASK-026: the Wazuh sync job now runs by default every 15 minutes as the system actor (set `NT_SECURITY_SYNC_ACTOR_ID` to attribute it to a named Owner). `assertCan` accepts only the exact frozen `SYSTEM_ACTOR` object, so no HTTP session can pass as it. The simulated Wazuh adapter returns no alerts, so no fake security events are created.
- TASK-028: scheduled access reviews (`accessReviews.startDue`, checked daily). When the newest review is older than `NT_ACCESS_REVIEW_DAYS` (default 90, quarterly; `0` disables), a review is opened, assigned to the first active Owner, and they are notified. Nothing is decided automatically. The cadence remains an Owner policy decision (REQUIRES DECISION).
- Web `/access`: reviews could be started but never decided or completed from the UI. Added a review screen (findings per grant, keep/revoke, own grants locked, save decisions, complete) with EN/AR strings. The grants table showed an empty permission column (`permissionKey` vs `permissionCode`), now fixed.
- Docs bug (not fixed): `docs/openapi.json` shows the platform approval body for `POST /access-reviews/{id}/decisions` because two Zod schemas share the name `decideBodySchema`; the real body is `{ decisions: [{ grantId, decision: keep|revoke, note? }] }`. The generator script (`scripts/generate-openapi.mjs`) did not come over in the repo split.
- Evidence: Vitest 38 files / 499 tests PASS. `npm run drill:security` against the live API: 30/30 (security sync with coverage notice; incident lifecycle detected to closed with invalid transition, early assignment and severity lowering rejected, assignee notified, evidence hash chain intact, secret scrubbed, closed incident refuses evidence; firewall preview, SSH lockout flagged, approval required, self approval blocked, approval bound to the change set and single use; access review start, complete refused while undecided, revoke removes the grant, complete). `npm run smoke`: 71 GET 2xx, 0 5xx, 12/12 boundary checks. Admin `vite build` OK. Scheduled security sync ran as the system actor; 0 `job.failure` events.
- Still NOT_RUN: real Wazuh API, real ufw on an isolated VPS (lockout test), shared-service inventory, browser click-through of the new review screen, independent review.

## Update — Phase 10 Owner operations extensions (TASK-033..036, nothing DONE)

Added by the Owner on 2026-11-15 and built before phase 09 (see DECISIONS.md). This changes the source rule "No direct dashboard root access / no arbitrary shell" for the Owner only.

- TASK-035 Add server by SSH: `POST /servers/ssh` tests the login (real SSH via `ssh2`), creates the server and stores the password AES-256-GCM encrypted with `CREDENTIAL_ENCRYPTION_KEY` (fails closed when missing). The host key is pinned on first connect; a changed key is refused (`SSH_HOST_KEY_MISMATCH`). The password is never returned, logged or audited. Also `GET/PUT/DELETE /servers/:id/ssh`, `POST /servers/:id/ssh/test`. New table `ServerCredential` (additive migration `20261115205212_server_credentials`). Owner only + MFA.
- TASK-036 File manager and terminal: SFTP routes under `/servers/:id/files` (list, view/edit up to 1 MB, upload/download up to 20 MB, new folder, rename, delete with recursive confirm; root and home protected). Terminal: one-time 30-second ticket (`POST /servers/:id/terminal/ticket`) then WebSocket `/api/v1/servers/terminal` (xterm.js in the web app; Vite proxy has `ws: true`). Every file change and terminal session is audited; the terminal transcript stores typed lines and replaces a line typed after a password prompt with `[REDACTED]`. Idle sessions close after 30 minutes.
- TASK-034 New project database: the New project form has a "Create a database" option (database server, environment, name). It uses the existing approval flow.
- TASK-033 Home quick actions: 18 shortcuts on the Overview page with live badges (pending approvals, open incidents, servers with SSH).
- Gap fixed while building TASK-034: the web app had no way to approve platform approvals (DNS, SSL, databases, firewall, restores) or to finish them after approval. The Approvals page now lists them with Approve/Reject for a different person and Finish for the requester; the browser remembers each approval-gated request (`services/approvalReplay.js`, localStorage, same browser only).
- Dev tooling: `npm run dev:ssh` starts a local SSH/SFTP test server on 127.0.0.1:2222 (user `tester`, password `secret-pass`, files in `cpanel-back/.data/dev-ssh`); tests use the same server (`scripts/lib/ssh-test-server.mjs`).
- Evidence: Vitest 39 files / 515 tests PASS (12 new SSH tests run the real SSH protocol: wrong password, unreachable host, missing key, owner-only, host key change, full file lifecycle, terminal with single-use ticket and sudo redaction). Live against the API: add server by SSH, wrong password 422, credential summary without password, 200 KB edit, 3 MB upload, download, delete, non-owner 403, anonymous 401; new project + database through approval and Finish 9/9; terminal over the API WebSocket with audited, redacted transcript and ticket reuse refused 4/4. Smoke 71 GET 2xx / 0 5xx, 12/12 boundary checks; security drill 30/30; admin `vite build` OK; EN/AR keys present for every new string.
- Not done / NOT_RUN: browser click-through of the new pages; a real VPS (only the local test SSH server was used); SSH key authentication (password only, by Owner decision); `docs/openapi.json` not regenerated (generator script missing since the repo split); a solo Owner still needs a second account to approve High/Critical actions.

## Update — environments, server details, cPanel home, phase 09 (nothing DONE)

- TASK-037: add environments to any project (`POST /projects/:id/environments`); environment variables per environment (list with secrets masked, set, import/export .env, reveal, delete, write the .env file to the server over SFTP), AES-256-GCM encrypted with `CREDENTIAL_ENCRYPTION_KEY`; audit records keys only. New table `ProjectEnvVar` (migration `project_env_vars`). 22 project types and 12 process managers. Web: new "Environment" tab on the project page.
- TASK-038: server details page `/servers/:id` with 10 tabs (overview with live system information over SSH, services with start/stop/restart/reload/status, network with firewall rules/preview/apply and listening ports, projects, domains, databases, security events, files, terminal, settings for SSH login and agent). API: `GET /servers/:id/ssh/info`, `POST /servers/:id/ssh/service` (service names validated; injection attempts rejected).
- TASK-039: home page redesigned like a hosting control panel: tool search, 8 collapsible tool groups (37 tools) with icons and badges, side column with general information, statistics, servers and recent activity.
- Translations: whole-app audit, 1,160 keys used in code, 0 missing in English or Arabic; 26 new audit action labels added in both languages.
- Phase 09: `npm run test:security` (43 checks), `npm run test:load` (564 req/s, p95 72 ms), `npm run drill:recovery` (PASS, restore 3.9 s); runbook rewritten with real commands; release acceptance matrix updated.
- Bugs found by the security tests and fixed: approval decisions checked state before permission (information leak); platform approvals list matched deployment approvals because of case-insensitive collation.
- Evidence: Vitest 40 files / 534 tests PASS; live checks 18/18 (environments, server details), 13/13 (phase 10), 30/30 (security drill), smoke 71 GET 2xx / 0 5xx; admin build OK.
- Still NOT_RUN: browser click-through, real VPS, independent review, staging rehearsal of the runbook, Owner sign-off.
