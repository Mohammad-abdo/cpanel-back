# Prd

Status: requirements/specifications, not implemented capabilities. Source: required.md sections 3,4,5,6,7,8,9.

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


