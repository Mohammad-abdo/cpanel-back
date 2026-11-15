# NodeTeam Control Platform

English requirements translation. Decorative images and corrupted display CSS omitted. Functional scope and phase order retained. Requirements are not implemented capabilities. Original attachments remain in conversation history; translated copies are not byte-identical originals.

## 1. Technology stack

Node.js LTS, Express JavaScript, Prisma ORM, MySQL8 metadata. React/Vite/JSX, MUI9, Tailwind, Motion (motion/react), Axios/TanStack Query, Zustand, Socket.IO. BullMQ/Redis, Zod, sessions/MFA, OpenAPI. Independent Go Agent, Prometheus, Loki, Restic, Wazuh. Vitest/Supertest/Playwright. Verify version compatibility before installation.

## 2. Architecture

NodeTeam Control is a multi-VPS Infrastructure, DevOps and Team Operations Platform for Ubuntu production servers running Node/PM2, Laravel, Apache and MySQL/PostgreSQL/MongoDB/Redis workloads. Owner controls resources, identities, changes, outcomes, domains, certificates, backups and security. Modular monolith API with separate workers and agents. React displays scoped data; API owns policies/approvals/reports; Prisma/MySQL metadata; Redis queues; Loki raw logs; Prometheus metrics. Gateway uses mTLS/job validation/scoped operations/audit. No direct dashboard root access. Control-plane failure must not stop applications.

## 3. Servers and projects

Server registration, discovery, CPU/RAM/swap/disk/network, processes, Systemd/PM2/Apache/Nginx, disk alerts, ports/connections, approved firewall/maintenance, Healthy/Warning/Critical, per-server access. Discover existing projects without redeploy or path changes. Preview shared-service restart impact. Project fields: name/slug/server/environment/type(Node/Laravel/WordPress/Static/Custom), repo/branch/commit, runtime/process manager, domains/SSL, ports, databases, team, deploys/backups/metrics/logs/alerts. Create/link/configure secrets/deploy/start/stop/restart/rollback/health/archive. Deployment: Queued -> Preparing -> Building -> Deploying -> Health Check -> Success/Failed/Rolled Back; record actor/timing/result per step.

## 4. Project Observability Center

Collect application/runtime-PM2/web-Apache-Nginx/database/deployment/jobs/security/audit logs. Live Socket.IO or SSE; time/project/server/severity/source filters; requestId/traceId/deploymentId; stack traces; first/last/count; error groups; deployment comparisons; commit/release links; authorized exports; error-rate alerts. Redact secrets before storage/display. Labels server_id/project_id/environment; backend gateway controls query scope/Loki tenancy. Error timing does not prove developer fault. Demo GoRide events are not production evidence.

## 5. Team Intelligence

Track professional platform/linked events, not personal device activity or keystrokes. Member identity/role/permissions/projects/servers/deployments/restarts/config/domain/SSL changes/denials/approvals/outcomes/last activity/incidents/audit. Reports: individual activity, project contribution, deployment success, changes, incident ownership, security, failed operations, workload, access, weekly/monthly summaries. Every metric opens original events. Link member/assignment/operation/commit/result/health/audit/report. Separate initiator/approver/executor. Unmapped SSH/GitHub identity remains External/Unattributed. GoRide/Medor/Vovus and dashboard counts are illustrative.

## 6. Project reports

Separate from monitoring/logs: uptime/outages, resources, requests/error rate/latency, slow endpoints, recurring errors, deployments/rollback, database health/slow queries, security, backup verification, team activity, incidents/resolution duration. Scheduled weekly PDF/Excel covers health/changes/deployments/errors/outages/resources/backup/SSL/team. Authorized recipients only.

## 7. Permissions

Owner ultimate control; Infrastructure Admin allowed servers; DevOps allowed deployment/services; Team Lead assigned projects/team; Developer granted actions; Security Analyst security analysis; Auditor logs/reports/audit; Viewer selected reads. Only designated Owner; no Team Lead self-escalation/new Owner/scope widening. Action+resource type+resource ID+environment+conditions. Permissions: project.logs.read, project.deploy.create, project.restart.execute, project.env.metadata.read, project.secret.rotate, project.backup.create/restore, server.metrics.read, server.firewall.update, server.service.restart, domain.create, ssl.issue, team.member.invite, team.permission.assign, audit.logs.read, report.team.export. Staging grants do not imply production. Low: metrics; Medium: single-service restart/backup; High: production deploy/sensitive DNS-SSL; Critical: production restore/DB deletion/SSH-firewall. High/Critical approvals/reverification/reason/impact/rollback. Enforce backend and Agent, not hidden buttons.

## 8. Backup recovery

Types: project files/uploads, consistent engine-specific database dump, configuration/reverse-proxy, full recovery set, optional pre-deployment, offsite. Scheduled->Queued->Snapshot/Dump->Encrypt->Upload->Verify->Retain. Restore: select->validate->impact preview->approval->safety backup->restore->health->audit. Isolated trial before production restore when possible; show replaced data/resources. Per-project frequency/retention/encryption/destination/restore permissions/verification/RPO/RTO. Immutable/object-lock when supported; separate offsite account so one compromised app cannot delete all backups.

## 9. Security Center

SSH successes/failures/trends, sessions/users/sudo, firewall/ports/unexpected services, file integrity, updates, malware/suspicious processes, certificate expiry and scoped alerts. Incident: Detected->Triaged->Assigned->Investigating->Contained->Resolved->Closed. Evidence/events/severity/owner/actions/timestamps. No guarantee of total compromise detection; untrusted hosts require independent evidence, not Agent data alone.

## 10. Prisma data model

MySQL metadata, not raw logs or high-frequency metrics. Identity: User Session MfaFactor ApiToken. Authorization: Role Permission RolePermission UserRole ResourceGrant. Teams: Team TeamMember ProjectMember. Infrastructure: Server ServerAgent ServerService ServerPort ServerSnapshot. Projects: Project ProjectEnvironment ProjectRuntime ProjectRepository. Deployment: Deployment DeploymentStep DeploymentApproval. Operations: OperationJob OperationExecution ApprovalRequest. Hosting: Domain DnsRecord SslCertificate DatabaseInstance ManagedDatabase DatabaseUser. Backups: BackupPolicy BackupRun BackupArtifact RestoreRun. Monitoring: MetricRule HealthCheck Alert AlertEvent. Logs: LogSource LogStream LogBookmark ErrorGroup. Security: SecurityEvent SecurityIncident IncidentAssignment. Reports: ReportDefinition ReportRun ReportSchedule ReportArtifact. Audit: AuditEvent ActivityEvent AccessReview. Notifications: Notification NotificationChannel NotificationPreference. ActivityEvent UUID; nullable actor/server/project/environment/operation IDs; category/action/resourceType/resourceId/result/source/correlationId/JSON metadata/occurredAt/createdAt. Index actor/time, project/time, server/time, category-action/time, correlationId. FK/index/retention details remain design work. Separate activity aggregates, audit security record, Loki logs, Prometheus metrics. Append-only audit replicated to independent tamper-resistant storage; Prisma alone cannot stop root/DB admin. Original diagram export CSS was corrupt.

## 11. Backend API

Feature modules own controller/validator/service/routes; optional repositories/policies. apps/api/src/config/common/modules/jobs/sockets and prisma/schema/migrations/seed; apps/worker; apps/web/src/app/layouts/modules/components/hooks/services/store/theme/routes/assets; agents/ubuntu-agent; packages/shared-contracts/permission-catalog/event-schemas; infrastructure/tests/docs. Modules auth/users/teams/servers/projects/deployments/domains/certificates/databases/backups/operations/monitoring/logs/security/incidents/reports/audit/notifications. /api/v1: auth login/mfa/verify/logout; users/:id/activity; roles/grants/access-reviews; servers/:id/metrics/services; projects/:id/health/logs/errors/deployments; deployments/:id; operations/:id/cancel; approvals/:id/approve; domains/:id/dns-records; certificates/:id/renew; backup-policies/backups/restores; security/events/incidents; reports/:id/runs/team; audit/events; notifications/preferences. Operation flow session/MFA/CSRF->scope->risk/approval->PENDING_APPROVAL or QUEUED->Agent validation->execute->result/audit/activity->Socket update->health. operationId/correlationId/idempotencyKey required. Full DTO/OpenAPI remains planned.

## 12. Frontend

Arabic/English product UI, RTL/LTR, light/dark, responsive desktop-first. English-only documentation. Palette background #0B1220 surface #121D2E teal #16B8A6 blue #5B8DEF amber #F59E0B/red critical. MUI grids/dialogs/forms/tabs; Tailwind layout; Motion functional transitions. Configure Emotion/CSS layers; reduced motion; no heavy log animations. Sidebar WORKSPACE Overview/My Activity/Notifications/Approvals; INFRASTRUCTURE Servers/Services/Network-Firewall/Storage; PROJECTS All/Deployments/Runtime/Logs/Errors; HOSTING Domains-DNS/SSL/Databases/Backups; INTELLIGENCE Monitoring/Security/Incidents/Reports/Team Analytics; ADMINISTRATION Team-Roles/Audit/Integrations/Settings. Server tabs Overview/Resources/Processes/Services/Network/Security/Backups/Logs/Operations/Settings. Project tabs Overview/Runtime/Deployments/Logs/Errors/Metrics/Domains/Database/Backups/Team/Activity/Reports/Settings. Member tabs Profile/Assigned Projects/Permissions/Activity/Deployments/Operations/Incidents/Reports/Access History.

## 13. Monitoring alerts

Prometheus metrics, Loki logs, MySQL events. Suggested CPU/memory 15s, disk60s, process15-30s, HTTP30-60s, SSL12h, backups after each and daily, security/activity event-driven. Tune to load. Rules sustained CPU5min, RAM/swap, low disk, project/health failure, error rate, SSL expiry, failed/stale backups, SSH spikes, external sensitive changes. Severity/deduplication/acknowledgment/escalation/history.

## 14. Non-functional

Isolate control plane; MFA/least privilege/mTLS; encrypted secrets/redaction; bounded retries/idempotency/timeouts; independent audit; multiple servers/distributed workers; pagination/streaming; separate retention; offsite/restore drills; platform recovery/Owner emergency; unit/integration/E2E/security/restore tests. Dashboard outage cannot stop customers. Agent reconnect cannot replay stale jobs.

## 15. Roadmap

00 Discovery: inventory/security baseline/recovery/database/API/design. 01 Core: API/Prisma/MySQL/login/MFA/Owner/RBAC/sessions/audit. 02 Agents/monitoring. 03 Projects/deployments/discovery/PM2/Laravel/Git/health/rollback/queue. 04 Observability/Loki/streaming/filters/errors/alerts. 05 Team activity/timeline/contribution/reports/PDF-Excel. 06 Domains/virtual hosts/DNS/SSL/databases. 07 Backup/offsite/restore/verification. 08 Security/incidents/firewall/approvals/access review. 09 Multi-server/load/security/recovery/handover. Do not reorder without explicit approval.

## 16. Acceptance

Enforce project isolation across API/socket/logs/downloads. Audit initiator/approver/executor/results. Test error reaches correct project without secrets. Reports match real events without duplicate counts. Successful/failed deployments include health and rollback. Backup then isolated restore matches files/data. Test domain issuance/renewal verified. Agent reconnect has no duplicates/unauthorized execution. Control-plane failure leaves projects running. Platform recovery verifies Owner emergency access.

## 17. Delivery

01-PRD;02-SRS;03-SYSTEM-ARCHITECTURE;04-DATABASE-SCHEMA;05-API-CONTRACTS;06-AGENT-SPECIFICATION;07-PERMISSIONS-MATRIX;08-UI-SCREENS;09-LOGGING-AND-MONITORING;10-TEAM-REPORTING;11-SECURITY-PLAN;12-BACKUP-RESTORE;13-IMPLEMENTATION-ROADMAP;14-TEST-PLAN;15-DEPLOYMENT-RUNBOOK. Detailed Prisma/DTO/screens/Agent contracts are separate deliverables, not implied implementation.

## 18. Decisions rollout

Required source stack and Owner control; independent secure Agent; separate control plane; MySQL metadata/Loki logs. Read-only before control. First useful rollout combines monitoring/discovery/project logs/team reports with identity/permissions/audit; introduce deploy/domain/SSL/restore gradually. This does not authorize changing numbered phases.
