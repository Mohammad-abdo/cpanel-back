# Backend features added in the SSH / live-operations workstream

Status: documentation of code that exists locally as of 2026-11-16. It is derived from reading source, not from running it. Nothing here is DONE. Independent review is pending and production is NOT_RUN. The work is adjacent to TASK-022 and early TASK-023 and does not show that prerequisite gates passed.

Sources read: `src/modules/{server-access,project-env,servers,projects,databases,domains}`, `prisma/schema.prisma`, migrations `20261115205212_server_credentials` and `20261115210830_project_env_vars`, `scripts/debug-inventory.mjs`, `tests/`. Routes are mounted under `/api/v1` in `src/routes.js`. `/servers` is mounted twice (server-access router first, then servers router), as is `/projects` (project-env first, then projects).

Guard legend:
- `session` = `requireSession()`.
- `mfa` = `requireSession({ requireMfa: true })`.
- `owner` = `mfa` plus a service check on `actor.isOwner` (`OWNER_ONLY`/`FORBIDDEN`).
- `rbac` = `assertCan` on a permission key, project and environment.

## Cross-cutting security controls

- Secrets (SSH password, DB admin password, env var values) are encrypted with AES-GCM via `platform.crypto.js` using `CREDENTIAL_ENCRYPTION_KEY`. Services fail closed when the key is missing (server-access encrypts a probe before touching the network).
- `ssh.connector.js` (ssh2): password auth only (`tryKeyboard: false`), host key pinned by SHA256 fingerprint in `ServerCredential.hostKeySha256`. A changed key gives 409 `SSH_HOST_KEY_MISMATCH`. Errors map to `SSH_AUTH_FAILED` 422, `SSH_TIMEOUT` 504, `SSH_UNREACHABLE` 502. Helpers: `execCommand` (output capped 64 KB, stderr 8 KB, timeout), `execScript` (`bash -s`, fixed script, args JSON-quoted), `openSftp`.
- The host key is recorded at first connect (trust on first use). Nothing verifies it out of band.
- Passwords are never returned by the API. Instance and credential responses expose only `hasAdminLogin` or metadata.
- DB passwords reach the remote host through a `chmod 600` temp `--defaults-extra-file` for MySQL or `PGPASSWORD` exported inside the script for Postgres. They are not passed as argv flags.
- Identifier checks: `assertSafeDbName`, `assertSafeDbUser`, `assertSafeIdent`; paths reject NUL bytes; service and PM2 names are regex-restricted; all validators are Zod `.strict()`.
- Audit events are written via `auditService.record` for every mutation (see per module lists). Env audit stores key names only, never values.

## Environment variables

| Variable | Used by | Notes |
| --- | --- | --- |
| `CREDENTIAL_ENCRYPTION_KEY` | server-access, project-env, databases, `scripts/debug-inventory.mjs` | Required. Present in `.env.example` (empty). No documented format or rotation procedure. |

No other new env vars were found. Size and time caps are code constants (below).

## Module: server-access (mount `/servers`)

Purpose: store an SSH login per server, then operate the server over SSH: info, systemd services, PM2, SFTP file manager, live DB browse/dump/restore, web terminal tickets, and an inventory scan/import that creates Project, Domain and DatabaseInstance records.

All routes use `owner` and a UUID `:id` params schema, except the first.

| Method | Path | Request | Behavior |
| --- | --- | --- | --- |
| POST | `/ssh` | body: `alias`, `host`, `port` (default 22), `username`, `password` | Tests login, creates Server plus encrypted ServerCredential, pins host key, seeds a first snapshot when possible. 409 `SERVER_ALIAS_TAKEN`. Audit `server.ssh.add`. |
| GET | `/:id/ssh` | none | Credential metadata, no secret. |
| PUT | `/:id/ssh` | body as above without alias | Re-tests and replaces credential. Audit `server.ssh.set`. |
| DELETE | `/:id/ssh` | none | Removes credential. Audit `server.ssh.remove`. |
| POST | `/:id/ssh/test` | none | Connects and updates `lastConnectedAt`. |
| GET | `/:id/ssh/info` | none | Runs `INFO_SCRIPT` (OS, CPU, memory, disk, services); persists a ServerSnapshot with SSH metrics. 504 `SSH_INFO_TIMEOUT`. |
| POST | `/:id/ssh/service` | `name` (`[A-Za-z0-9@._-]{1,100}`), `action` start/stop/restart/reload/status/enable/disable | `systemctl`. Audit `server.service.<action>` with exit code. |
| GET | `/:id/ssh/pm2` | none | `pm2 jlist` (tries several PM2 homes, nvm paths, sudo -n). 404 `PM2_NOT_FOUND`, 504 `PM2_TIMEOUT`. |
| POST | `/:id/ssh/pm2` | `name` (`[A-Za-z0-9._:-]{1,100}`), `action` start/stop/restart/reload/delete/logs/describe | PM2 control; audit `server.pm2.<action>`. stop/restart/reload are High risk and gated by `platform.gate` (action `pm2.<action>`, resource `server`, binding = process name): optional `reason`, `rollbackNote`, `approvalId`; 202 `{approvalRequired, approvalId}` until a different person approves, then replay with `approvalId`. start/delete/logs/describe are not gated. |
| GET | `/:id/ssh/htop` | none | Fixed `HTOP_SCRIPT` over SSH (two `/proc/stat` samples + `ps` top 80). Returns load, memory/swap, per-CPU %, process rows. Read-only; no interactive TTY and no kill/renice. 504 `SSH_HTOP_TIMEOUT`. UI: server detail **Htop** tab (`HtopPanel`). |
| GET | `/:id/ssh/db/:engine/schemas` | `engine` mysql or postgres | Lists schemas. |
| GET | `/:id/ssh/db/:engine/tables` | query `db` | Lists tables. |
| GET | `/:id/ssh/db/:engine/columns` | query `db`, `table` | Columns. |
| GET | `/:id/ssh/db/:engine/rows` | query `db`, `table`, `limit` 1-200, `offset` 0-100000 | Row preview. |
| POST | `/:id/ssh/db/:engine/query` | body `sql` (max 20000), `db?` | Single statement only (`DB_SQL_MULTI`). Audit `server.db.query.read` or `.write` with 200-char `sqlPreview`. |
| GET | `/:id/files` | query `path?` | SFTP directory listing. |
| GET | `/:id/files/content` | query `path` | Read text. Over 1 MB returns `tooLarge`. |
| PUT | `/:id/files/content` | body `path`, `content` (max 1 MB); route-level JSON limit 1 MB + 64 KB | Write. Audit `server.file.write` with size and sha256. |
| POST | `/:id/files/upload` | raw body up to 20 MB, query `path` | Upload. Audit with sha256. |
| GET | `/:id/files/download` | query `path` | Download up to 20 MB. |
| POST | `/:id/files/mkdir` | body `path` | Audit `server.file.mkdir`. |
| POST | `/:id/files/rename` | body `from`, `to` | Audit `server.file.rename`. |
| DELETE | `/:id/files` | query `path`, `recursive` true/false | Refuses `/` and home (`PATH_PROTECTED`); recursive cap 5000 entries; non-empty folder needs `recursive`. Audit `server.file.delete`. |
| POST | `/:id/terminal/ticket` | none | Single-use ticket, TTL 30 s. Consumed by the WebSocket in `server.js` (`server-access.terminal.js`), which records commands and redacts sudo passwords. |
| POST | `/:id/inventory/scan` | none | Runs fixed `INVENTORY_SCRIPT` (time-boxed `find` and `grep`, 90 s, 768 KB output). Read-only on the remote host. Returns projects, domains, databases plus a `debug` block. Audit `server.inventory.scan`. |
| POST | `/:id/inventory/import` | body `projects[]`, `domains[]`, `databases[]` (mysql/postgres), `importAll` | Creates records from selection. Archives earlier junk discoveries (`node_modules` paths). Audit on completion. |

Service-only methods without a route in this module: `dbDump`, `dbRestore`, `inspectSite` (`site-live.scan.js`), `createTicket`/`openShell`. They are reached through databases and projects routes below.

Live DB behavior (`db-live.scan.js`):
- MySQL via `mysql` CLI and Postgres via `psql`. With no saved login it falls back to `sudo -n`/debian.cnf/peer probes.
- Dump: MySQL `mysqldump --single-transaction --routines --triggers --events --hex-blob` (login required, 409 `DB_LOGIN_REQUIRED`); Postgres `pg_dump`/`pg_dumpall --no-role-passwords`. Output goes to a `/tmp/` file, then is read back over SFTP. Caps: 80 MB (`MAX_DB_DUMP_BYTES`, `DB_DUMP_TOO_LARGE`), empty dump rejected.
- Restore: requires `confirm` equal to the db name or `ALL`; payload at least 8 bytes and at most 80 MB.
- `isMutatingSql` is used only to label audit events. It does not block writes.

Caps: edit 1 MB, upload/download 20 MB, DB dump/restore 80 MB, recursive delete 5000, ticket TTL 30 s, connector timeout 30 s for the shared instance.

Tests: `tests/server-access.test.js` (add server, wrong password, unreachable, no key, non-owner, host key change, SFTP, info/service, terminal ticket and redaction); `src/modules/server-access/server-inventory.scan.test.js` (parse and junk filter). Local only, with a fake connector.

## Module: project-env (mount `/projects`)

Purpose: per-environment encrypted environment variables, `.env` import/export, and sync with the remote server `.env`.

| Method | Path | Guard | Request | Behavior |
| --- | --- | --- | --- | --- |
| POST | `/:id/environments` | mfa + Owner | `code` (`^[a-z][a-z0-9-]{0,31}$`), `displayName` | Adds environment. 409 `ENVIRONMENT_EXISTS`. Audit `project.environment.add`. |
| GET | `/:id/environments/:envId/vars` | session + rbac | none | Secret values masked (`value: null`); `canEdit` flag. |
| PUT | `.../vars` | mfa + rbac configure | `vars[]` (key regex, value max 32 KB, `isSecret`), max 500; route JSON limit 600 KB | Upsert. Audit `project.env.set` with keys only. |
| POST | `.../vars/import` | mfa + rbac | `text` max 512 KB, `markSecrets` | Parses dotenv; secret-looking keys auto-marked. Audit `project.env.import`. |
| GET | `.../vars/export` | mfa + rbac | none | Returns dotenv text. Audit `project.env.export`. |
| POST | `.../vars/write-server` | mfa + rbac | `path` absolute, max 1024 | Writes dotenv to server via `serverAccess.write`. Audit `project.env.write_server`. |
| POST | `.../vars/pull-server` | mfa + rbac | `path?` (default `discoveredPath/.env`), `import`, `markSecrets` | Reads remote `.env` via SFTP (1 MB cap, text only), optionally upserts. 409 `PROJECT_PATH_UNKNOWN`. Audit `project.env.pull_server`. |
| GET | `.../vars/:key/reveal` | mfa + rbac | none | Decrypts one secret. Audit `project.env.reveal`. |
| DELETE | `.../vars/:key` | mfa + rbac | none | Audit `project.env.delete`. |

Controls: environment must belong to project (404), archived project 409, environment-scoped RBAC so staging access does not expose production; read-only users see non-secret values only. `looksSecret` regex marks SECRET, PASSWORD, TOKEN, KEY, DSN, DATABASE_URL and similar.
DB: `ProjectEnvVar(environmentId, key unique together, valueEnc BLOB, isSecret, updatedById)`; cascade delete.
Tests: `tests/project-env.test.js` (parsing, masking, reveal, audit keys only, staging isolation, read-only, fail closed, write-server, add environment). Pull-server has no test.

## Module: servers (mount `/servers`)

Purpose: server inventory records. Responses for the Owner include SSH credential metadata (`sshFor`).

| Method | Path | Guard | Request |
| --- | --- | --- | --- |
| GET | `/` | session | query `listServersQuerySchema` |
| GET | `/services`, `/ports` | session | `fleetReadQuerySchema` |
| GET | `/runtimes` | session | none, no validator |
| POST | `/` | mfa + Owner | `createServerBodySchema` |
| GET | `/:id` | session | uuid params |
| PATCH | `/:id` | mfa + Owner | `updateServerBodySchema` |
| POST | `/:id/archive` | mfa + Owner | `archiveServerBodySchema` |
| POST | `/:id/enrollment` | mfa + Owner | issues agent enrollment token |
| GET | `/:id/metrics` | session | `metricsQuerySchema` |

Behavior added in this workstream: the list shows status, CPU, memory, disk and last report from agent snapshots or SSH snapshots; soft archive. Tests: `tests/agents-servers.test.js` (agent focused; SSH snapshot presentation is not specifically asserted). Read access is scoped by `createScope`.

## Module: projects (mount `/projects`)

Purpose: project registry with discovery, linking, lifecycle, team/member access, and live SSH runtime.

| Method | Path | Guard | Notes |
| --- | --- | --- | --- |
| GET | `/` | session | list (scoped) |
| POST | `/` | mfa | create |
| POST | `/discover` | mfa + Owner | records agent or scan candidates as `discovered` |
| GET | `/:id`, `/:id/overview`, `/:id/members`, `/:id/teams`, `/:id/restart-impact` | session | read |
| GET | `/:id/live` | mfa + Owner | `inspectSite` over SSH using `runtime.metaJson.discoveredPath`; returns PM2 matches, runtime info |
| POST | `/:id/pm2` | mfa + Owner | body `action` start/stop/restart/reload/delete/logs/describe, optional `name`; default target is first live-matched process; calls `serverAccess.pm2Control`; audit `project.pm2.<action>`. stop/restart/reload use the same gate (approval is bound to the server and process name; 202 on first call; replay with `approvalId`; no project audit until it runs) |
| POST | `/:id/teams`, DELETE `/:id/teams/:teamId` | mfa | link/unlink team |
| POST/PATCH/DELETE | `/:id/members[/:userId]` | mfa | project role lead/developer/viewer |
| POST | `/:id/link` | mfa + Owner | adds environments, `discovered` to `active` |
| PATCH | `/:id`, POST `/:id/archive` | mfa | configure, archive with reason |
| POST | `/:id/lifecycle/:action` | mfa | start/stop/restart via approval-aware operation queue (not inline SSH) |

Tests: `tests/phase3-projects-deployments.test.js`, `tests/phase11-projects-detail.test.js`, project teams tests. No test covers `/live` or `/pm2`.

## Module: databases (mount `/databases`)

Purpose: instance registry, managed databases/users (simulated adapters), and live browse/dump/restore of an instance over SSH using an encrypted admin login.

| Method | Path | Guard | Notes |
| --- | --- | --- | --- |
| GET | `/`, `/instances`, `/instances/:id` | session | list/get; `adminSecretEnc` stripped, `hasAdminLogin` returned |
| POST | `/instances` | mfa | register; optional `adminSecretRef` (reference string only, regex restricted) |
| PUT | `/instances/:id/login` | owner | body username/password; encrypted into `adminSecretEnc`; audited without password |
| DELETE | `/instances/:id/login` | owner | clears login |
| GET | `/instances/:id/live/{schemas,tables,columns,rows}` | owner | proxies to server-access db browse; needs `serverId` (409 `INSTANCE_NO_SERVER`); mysql/postgres only |
| POST | `/instances/:id/live/query` | owner | single statement |
| POST | `/instances/:id/live/dump` | owner | body `db` nullable; returns dump |
| POST | `/instances/:id/live/restore` | owner | raw body up to 80 MB, query `db?`, `confirm`, optional `reason`, `rollbackNote`, `approvalId`. Critical (`db.restore.live`): typed confirm is checked first, then `platform.gate` bound to target + SHA-256 of the dump; 202 until approved, replay the same file with `approvalId` |
| POST | `/` | mfa + rbac DATABASE | create database (MySQL only; reserved names refused) |
| POST | `/:id/users` | mfa + rbac | grants read or readwrite; password returned once, never stored |
| POST | `/:id/drop` | mfa + rbac | needs `confirmName` equal db name and a verified backup within 24 h (`SAFETY_BACKUP_REQUIRED`) |

Tests: `tests/phase6-databases.test.js` covers the managed-database flow. Live login/browse/dump/restore have little or no direct test (one live/dump/restore keyword match only).
DB: `DatabaseInstance.adminUsername String?`, `adminSecretEnc Bytes? @db.Blob`. These were applied locally with `prisma db push` and have NO migration file (see gaps).

## Module: domains (mount `/domains`)

Purpose: domain records, web server vhost generation/apply, DNS changes, and raw conf editing.

| Method | Path | Guard | Request |
| --- | --- | --- | --- |
| GET | `/` | session | `listDomainsQuerySchema` |
| POST | `/` | mfa + rbac DOMAIN | `createDomainBodySchema` |
| GET | `/:id` | session | scoped |
| GET | `/:id/conf` | mfa + Owner | reads conf over server access |
| PUT | `/:id/conf` | mfa + Owner | `content` max 1 MB |
| POST | `/:id/vhost/preview` | mfa + rbac | `upstreamPort`, `webserver` nginx/apache, `environmentId` |
| POST | `/:id/vhost/apply` | mfa + rbac + approval | adds `reason`, `rollbackNote`, `approvalId`; approval binds to sha256 of the rendered config; returns `approvalRequired` when not approved |
| POST | `/:id/dns` | mfa + rbac + approval | `op` upsert/remove, type A/AAAA/CNAME/TXT/MX, `ttl` 60-86400, approval bound to the change hash |

Tests: `tests/phase6-domains.test.js`. Conf read/write over SSH is not obviously covered.

## Prisma changes

- `ServerCredential` (migration `20261115205212_server_credentials`): `serverId` unique FK cascade, `host`, `port` 22, `username`, `authType` password, `secretEnc` BLOB, `hostKeySha256`, `lastConnectedAt`, `createdById`.
- `ProjectEnvVar` (migration `20261115210830_project_env_vars`): see project-env.
- `DatabaseInstance.adminUsername` and `adminSecretEnc`: schema only, no migration.
- `ProjectRuntime.metaJson` carries `discoveredPath`. `ServerSnapshot` stores SSH metrics.

## Scripts

`scripts/debug-inventory.mjs [serverId]` is a developer probe. It decrypts a stored credential with `CREDENTIAL_ENCRYPTION_KEY`, connects, and runs `INVENTORY_SCRIPT`, printing raw output. It has a hardcoded default server UUID and prints remote data to the console. Do not run it against production.

## Known gaps and risks

1. `adminUsername`/`adminSecretEnc` have no committed migration; `docs/04-DATABASE-SCHEMA.md` does not list `ServerCredential`, `ProjectEnvVar` or those columns.
2. `docs/05-API-CONTRACTS.md` does not list any of the routes above (OpenAPI is generated and unreviewed).
3. Raw SQL endpoints (`/ssh/db/:engine/query`, `/live/query`) permit writes; the "mutating" flag only labels the audit. `sqlPreview` (200 chars) may capture secrets. No statement allow-list or approval gate.
4. DB restore and live dump run as the stored admin login with no approval workflow, safety backup, or operation record. Only an owner-typed confirm string guards restore. UPDATE 2026-11-16: live restore is now also approval-gated (critical); safety backup and operation record are still missing.
5. Host key is trusted on first use. Password auth only; no key auth.
6. Routes lacking dedicated tests: pull-server, `/projects/:id/live`, `/projects/:id/pm2`, server PM2 routes, live DB browse/dump/restore, inventory scan/import (only the parser is tested), `GET /servers/runtimes`.
7. `GET /servers/runtimes` has no validator. File routes have no rate limit beyond global.
8. `/projects/:id/pm2` and `/servers/:id/ssh/pm2` use `sudo -n` with PM2 home probing of `/root/.pm2` and `/home/*/.pm2`, which is broad privilege.
9. Terminal command recording redacts sudo passwords only; other secrets typed in a shell may be recorded.
10. Project pm2 control bypasses the approval-aware operation queue that project lifecycle uses. UPDATE 2026-11-16: stop/restart/reload now go through `platform.gate` (High); they still do not use the operation queue.
11. Several service files are large (`server-access.service.js` about 1190 lines) and mix SSH, DB and inventory logic. This conflicts with the one-module-per-concern intent in `docs/BACKEND-MODULES.md`.
12. Formal Vitest and browser evidence for these features is not recorded as passing (see `docs/PLAN/SESSION-2026-11-16.md`).
