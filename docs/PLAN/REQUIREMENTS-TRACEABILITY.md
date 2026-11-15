# Requirement traceability

| Source sections | Project requirement | Phase | Task |
|---|---|---|---|
| required.md 3,14,15 | Resources, projects, PM2/Laravel/Apache, ports, engines, backups, RPO/RTO | 00 | [TASK-001](TASKS/TASK-001.md) |
| required.md 2,7,10,11 | All model relationships/indexes; /api/v1 DTOs; Agent mTLS job envelope | 00 | [TASK-002](TASKS/TASK-002.md) |
| required.md 12 | Six navigation groups, server/project/member tabs, RTL/LTR, themes, CSS layers | 00 | [TASK-003](TASKS/TASK-003.md) |
| required.md 1,11 | Express JavaScript, Prisma/MySQL8, React Vite JSX, BullMQ/Redis | 01 | [TASK-004](TASKS/TASK-004.md) |
| required.md 7,11,14 | User/Session/MfaFactor, login/mfa/logout, expiry/revocation/recovery | 01 | [TASK-005](TASKS/TASK-005.md) |
| required.md 5,7 | Roles/grants/Team/TeamMember/ProjectMember with action/resource/environment | 01 | [TASK-006](TASKS/TASK-006.md) |
| required.md 5,10,14 | Append-only AuditEvent, ActivityEvent, independent replication and actor roles | 01 | [TASK-007](TASKS/TASK-007.md) |
| required.md 2,14 | Server/ServerAgent identity, Go service and scoped gateway | 02 | [TASK-008](TASKS/TASK-008.md) |
| required.md 3,15 | Systemd/PM2/Apache/Nginx, snapshots, processes/network/storage | 02 | [TASK-009](TASKS/TASK-009.md) |
| required.md 3,13 | Prometheus CPU/RAM/swap/disk/network and health/connectivity | 02 | [TASK-010](TASKS/TASK-010.md) |
| required.md 7,11 | OperationJob/Execution/ApprovalRequest, BullMQ/cancel/impact preview | 03 | [TASK-017](TASKS/TASK-017.md) |
| required.md 3,11 | Project/environment/runtime/repository/types/secret configuration/PM2 lifecycle | 03 | [TASK-018](TASKS/TASK-018.md) |
| required.md 3,16 | Deployment/Step/Approval, commit/release, actor/timing/results | 03 | [TASK-019](TASKS/TASK-019.md) |
| required.md 4,13 | Application/runtime/web/database/deployment/jobs/security/audit sources | 04 | [TASK-011](TASKS/TASK-011.md) |
| required.md 4,7 | Socket.IO, filters, request/trace/deployment IDs, stack/bookmarks | 04 | [TASK-012](TASKS/TASK-012.md) |
| required.md 4,13 | First/last/count, deploy comparison, thresholds/dedup/ack/escalation | 04 | [TASK-013](TASKS/TASK-013.md) |
| required.md 5 | Assignments/grants/deploy/restart/config/denials/approvals/incidents/last activity | 05 | [TASK-014](TASKS/TASK-014.md) |
| required.md 5,6 | Individual/contribution/deployment/changes/incidents/security/failures/workload/access and project metrics | 05 | [TASK-015](TASKS/TASK-015.md) |
| required.md 5,6 | ReportDefinition/Run/Schedule/Artifact and authorized recipients | 05 | [TASK-016](TASKS/TASK-016.md) |
| required.md 3,11,15 | Domain/DnsRecord, Apache/Nginx virtual hosts and provider integration | 06 | [TASK-020](TASKS/TASK-020.md) |
| required.md 11,13,16 | SslCertificate, renew operations and expiry monitoring | 06 | [TASK-021](TASKS/TASK-021.md) |
| required.md 3,10,15 | DatabaseInstance/ManagedDatabase/DatabaseUser and engine inventory | 06 | [TASK-022](TASKS/TASK-022.md) |
| required.md 8 | Restic policies/runs/artifacts, uploads/config/dumps/full recovery/pre-deploy | 07 | [TASK-023](TASKS/TASK-023.md) |
| required.md 8,14 | Per-project schedules/destination/encryption/verification/RPO/RTO and independent storage | 07 | [TASK-024](TASKS/TASK-024.md) |
| required.md 8,16 | Validate/preview/approval/safety backup/restore/health/audit | 07 | [TASK-025](TASKS/TASK-025.md) |
| required.md 9 | SSH/users/sessions/sudo/firewall/ports/services/FIM/updates/malware signals | 08 | [TASK-026](TASKS/TASK-026.md) |
| required.md 9 | Detected/Triaged/Assigned/Investigating/Contained/Resolved/Closed | 08 | [TASK-027](TASKS/TASK-027.md) |
| required.md 3,7,9 | Firewall/SSH/high-critical gates/shared-service impact and reviews | 08 | [TASK-028](TASKS/TASK-028.md) |
| required.md 2,14,16 | Multiple agents/workers, pagination/streaming, measured load budgets | 09 | [TASK-029](TASKS/TASK-029.md) |
| required.md 14,16 | Penetration tests, offsite control-plane restore and emergency access | 09 | [TASK-030](TASKS/TASK-030.md) |
| required.md 16,17 | All permissions/audit/log/report/deploy/backup/SSL/Agent/recovery evidence and15 documents | 09 | [TASK-031](TASKS/TASK-031.md) |

See each task for acceptance/tests. This is not proof of implementation.

## Section-to-implementation matrix (required.md 1-18)

Generated from repository inspection on 2026-11-15. Status vocabulary: IMPLEMENTED_LOCAL_SIMULATED (code and local tests exist; Prisma is an in-memory double in tests; executors simulated; no production verification), PARTIAL, NOT_STARTED, REQUIRES_DECISION. No row is independently reviewed or DONE; see [review packets](../REVIEW/PACKETS/README.md).

| Section | Modules (apps/api/src/modules unless noted) | Tests (apps/api/tests) | Docs | Status and gaps |
|---|---|---|---|---|
| 1 Stack | api, apps/web (React/Vite/MUI/Tailwind/Motion/Axios/TanStack/Zustand), apps/worker (bullmq, ioredis declared) | health, module-generator | docs/README.md, DECISIONS.md | PARTIAL: Socket.IO, Loki, Prometheus, Wazuh, Playwright, Supertest-based E2E not integrated; BullMQ wiring unverified. REQUIRES_DECISION for unapproved dependencies |
| 2 Architecture | agents, servers, operations, apps/worker, agents/ubuntu-agent (Go) | agents-servers, worker-scheduler, Go parse_test/config_test | docs/03-SYSTEM-ARCHITECTURE.md | PARTIAL: modular monolith present; Go agent not built/run (toolchain absent); interim key credential, not mTLS |
| 3 Servers and projects | servers, projects, deployments, domains, certificates, databases, firewall | agents-servers, phase3-*, phase6-*, phase8-firewall-access | docs/06, 15 | IMPLEMENTED_LOCAL_SIMULATED: real server discovery and PM2/Laravel/Apache actions NOT_RUN |
| 4 Observability | logs, monitoring | phase4-logs, phase4-observability | docs/09 | PARTIAL: redaction, filters, error groups, alerts local; Loki and Socket.IO live streaming not integrated (logs.stream.js only) |
| 5 Team Intelligence | members, activity, audit | phase5-members, audit-wiring | docs/10 | IMPLEMENTED_LOCAL_SIMULATED |
| 6 Project reports | reports, apps/worker scheduler | phase5-reports, worker-scheduler | docs/10 | PARTIAL: PDF/Excel generation and email delivery unverified against real recipients |
| 7 Permissions | rbac, teams, users, operations, common/scope.js, packages/permission-catalog | rbac-roles-evaluation, rbac-teams, scope-isolation, phase3-operations | docs/07 | IMPLEMENTED_LOCAL_SIMULATED: approval permission reuses action scope (no dedicated catalog entry); CSRF not found in source |
| 8 Backup recovery | backups, restores | phase7-backups, phase7-restores | docs/12, runbooks/BACKUP-RESTORE-OPERATIONS.md | IMPLEMENTED_LOCAL_SIMULATED: Restic, real encryption/upload and isolated restore NOT_RUN. REQUIRES_DECISION for offsite target |
| 9 Security Center | security, incidents, firewall, access-reviews | phase8-incidents-security, phase8-firewall-access, phase9-security | docs/11, runbooks/INCIDENT-RESPONSE.md | PARTIAL: Wazuh not integrated; incident lifecycle local |
| 10 Prisma model | apps/api/prisma/schema.prisma (61 models), migrations, seed.js | storage-durable | docs/04 | PARTIAL: schema and migrations exist; schema coverage versus the section 10 list not audited; MySQL used on local dev only |
| 11 Backend API | all modules; docs/openapi.json generated (142 operations) | all route-level tests | docs/05, openapi.json | PARTIAL: OpenAPI covers paths, params and request bodies; response DTOs not modeled; several section 11 paths (notifications, backup-policies naming) differ or are absent; no notifications module |
| 12 Frontend | apps/web/src (modules for 16 areas, i18n) | none (no web tests) | docs/08, design-system | PARTIAL: UI built; Arabic/RTL and responsive behavior not tested; no Playwright |
| 13 Monitoring alerts | monitoring (rules, alerts), servers | phase4-observability, agents-servers | docs/09 | PARTIAL: rules and lifecycle local; Prometheus intervals not wired |
| 14 Non-functional | auth, audit, operations, platform, common/middleware | auth-guard, security-fixes, phase9-*, worker-scheduler | docs/11 | PARTIAL: idempotency, redaction, rate limits local; mTLS, load budgets, offsite audit replication NOT_RUN |
| 15 Roadmap | n/a | n/a | docs/PLAN/MASTER-PLAN.md, 13 | PARTIAL: Phase 00 gates (inventory, security baseline, RPO/RTO) UNKNOWN or REQUIRES_DECISION; later phases built historically ahead of gates |
| 16 Acceptance | platform, restores, deployments, logs | phase9-platform, phase7-restores, phase3-*, scope-isolation | docs/14, runbooks/ | PARTIAL: local simulated evidence only; no live acceptance run |
| 17 Delivery | docs/01-15 | n/a | docs/ | PARTIAL: all 15 documents exist; several are summaries (for example 05 DTO detail now in openapi.json); not independently reviewed |
| 18 Decisions rollout | n/a | n/a | docs/DECISIONS.md | REQUIRES_DECISION: rollout order and production gates need Owner confirmation |
