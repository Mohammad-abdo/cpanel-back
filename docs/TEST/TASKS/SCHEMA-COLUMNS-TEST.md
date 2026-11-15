# SCHEMA-COLUMNS test record

Scope: additive columns DatabaseInstance(host, port, adminSecretRef), ReportDefinition(kind, projectId, paramsJson); certificates list investigation; Arabic gaps in ReportsPage.

## Commands and results

| Command (cwd) | Result |
| --- | --- |
| `npx prisma validate` (apps/api) | PASS, schema valid |
| `npx prisma migrate dev --name instance_and_report_columns --skip-generate` (apps/api) | PASS, applied `20261115171615_instance_and_report_columns` to local dev DB |
| migration.sql inspection | PASS, only `ALTER TABLE ... ADD COLUMN` (6 nullable columns); no DROP/DELETE/TRUNCATE |
| `npx vitest run` (apps/api) | PASS, 32 files, 310 tests (includes tests/phase11-schema-columns.test.js) |
| `npx vite build` (apps/web) | PASS, built (chunk-size warning only) |
| `prisma generate` | NOT_RUN by instruction (running API holds the engine file) |

## Certificates finding

Read-only DB query: SslCertificate has 0 rows; 9 ApprovalRequest rows for `ssl.issue` are `pending`. `ssl.issue` is high risk, so POST /certificates/domains/:id/issue answers HTTP 202 `approvalRequired` and creates no certificate until an approved request is replayed with `approvalId`. The list query and scope are correct. The seeding treated 202 as success. Regression test: phase11-schema-columns.test.js (list empty before approved retry, one active certificate after).

## NOT_RUN (needs regenerated Prisma client and restarted API)

- Live POST /databases/instances persisting host/port/adminSecretRef; instances list returning them.
- Live POST /reports/definitions persisting kind/projectId/paramsJson.
- Until regeneration, the services retry without new fields and return `schemaPending: true` (covered by mocked tests only).
- Arabic rendering of report types and cron descriptions: build only, no browser check.
