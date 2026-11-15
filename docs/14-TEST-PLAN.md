# Test Plan

Status: requirements/specifications, not implemented capabilities. Source: required.md sections 16.

## 16. Acceptance

Enforce project isolation across API/socket/logs/downloads. Audit initiator/approver/executor/results. Test error reaches correct project without secrets. Reports match real events without duplicate counts. Successful/failed deployments include health and rollback. Backup then isolated restore matches files/data. Test domain issuance/renewal verified. Agent reconnect has no duplicates/unauthorized execution. Control-plane failure leaves projects running. Platform recovery verifies Owner emergency access.

## Current test inventory

Recorded 2026-11-15. Command run once: `cd apps/api && npx vitest run` (Vitest 5.1.0). Result: 29 files, 292 tests, 292 passed, 0 failed. All tests use an in-memory Prisma double and simulated executors, so this is local simulated evidence only, not production or live-database verification. Counts are tests per file.

| Test file (apps/api/tests) | Tests | Area |
|---|---|---|
| agents-servers | 12 | Agent enrollment, auth, reports, server inventory |
| audit-wiring | 4 | Audit events wired to services |
| auth-guard | 3 | Session middleware |
| auth.service | 4 | Login, MFA flow |
| health | 7 | Health endpoint, app setup |
| module-generator | 2 | Module layout rule |
| phase3-operations | 17 | Operation queue, approvals |
| phase3-projects-deployments | 21 | Projects, deployments, rollback |
| phase4-logs | 4 | Log ingestion |
| phase4-observability | 17 | Logs search, error groups, alerts |
| phase5-members | 7 | Member profile, identity mapping |
| phase5-reports | 18 | Reports, schedules |
| phase6-certificates | 11 | SSL issue/renew |
| phase6-databases | 9 | Managed databases |
| phase6-domains | 16 | Domains, vhosts, DNS |
| phase7-backups | 17 | Backup policies, retention, verify |
| phase7-restores | 11 | Restore flow |
| phase8-firewall-access | 15 | Firewall, access reviews |
| phase8-incidents-security | 16 | Incidents, security events |
| phase9-platform | 15 | Fleet, break-glass, platform approvals |
| phase9-security | 14 | Security test suite |
| rbac-roles-evaluation | 11 | Role evaluation |
| rbac-teams | 13 | Teams |
| scope-isolation | 6 | Project/server scope isolation |
| security-fixes | 6 | Remediation regressions |
| storage-durable | 3 | Durable storage |
| totp | 2 | TOTP |
| users.service | 4 | Users |
| worker-scheduler | 7 | Worker scheduler |

Other tests: Go `agents/ubuntu-agent/internal/collector/parse_test.go` and `config/config_test.go` exist but NOT_RUN (Go toolchain absent). No web, worker-package, Playwright, E2E, load, penetration or live restore tests exist. The generated `docs/openapi.json` was structurally checked (JSON parse, `$ref` resolution, security entry per operation) by an ad hoc script, not a committed test.

Required section 16 scenarios without live evidence: backup-then-isolated-restore data match, domain issuance on real DNS, agent reconnect replay on a real agent, control-plane failure with running projects, Owner emergency access drill. Status NOT_RUN.


