# Operational handover: phases 06 to 09 (TASK-031 input)

Status: DRAFT for review. Written from the implementation; nothing here was verified on a real server.

## Components and mount points
| Module | Router export | Mount path |
| --- | --- | --- |
| domains | domainsRouter | /domains |
| certificates | certificatesRouter | /certificates |
| databases | databasesRouter | /databases |
| backups | backupsRouter | /backups |
| restores | restoresRouter | /restores |
| security | securityRouter | /security |
| incidents | incidentsRouter | /incidents |
| firewall | firewallRouter | /firewall |
| access-reviews | accessReviewsRouter | /access-reviews |
| platform (approvals, fleet, readiness, break-glass) | platformRouter | /platform |

## Approval model
Privileged actions call `platform.gate`. The first call returns HTTP 202 with an approval id and impact preview. A different user holding `platform.approval.decide` approves. The requester repeats the call with `approvalId`. Approvals expire after 24 hours, are single use, are bound to the action, resource and exact change, and cannot be self-approved.

## Environment variables (names only, values never in docs)
- `BACKUP_ENCRYPTION_KEY`: 32 bytes as 64 hex characters or base64. Required for backups and restores. Missing key fails closed.
- `EMERGENCY_RECOVERY_CODE_SHA256`: SHA-256 hex of the offline recovery code. Required for break-glass.

## Adapters
`platform.wiring.js` supplies simulated adapters. Real adapters for DNS provider, web server reload, ACME client, MySQL administration, restic and mysqldump, ufw, Wazuh API and fleet probing must implement the interfaces in `platform.adapters.js`. Until then every result carries `simulated: true`.

## Known gaps
- Break-glass is an audited time window. rbac does not yet widen permissions during the window.
- Evidence, firewall changes and restore previews are stored as audit events or inside ApprovalRequest.impactJson because the schema has no dedicated tables.
- Periodic jobs (certificate expiry scan, Wazuh sync, backup schedules, scheduled artifact verification, retention) are not scheduled; no worker wiring exists.
- Application-level retention guard keeps the 3 newest verified sets, but storage-level immutability is UNKNOWN.
- Automatic rollback after a failed in-place restore is not implemented.

## Proposed schema changes (not applied, apps/api/prisma/schema.prisma is not owned here)
- BackupPolicy: `kindsJson Json?`. BackupRun: `trigger String?`.
- RestoreRun: `approvalRequestId String?`, `safetyBackupRunId String?`, `mode String?`, `previewJson Json?`.
- New `IncidentEvidence` (incidentId, seq, type, summary, contentHash, prevHash, chainHash, createdById, createdAt) and `IncidentAction`.
- New `FirewallChange` (serverId, changesJson, windowStart, windowEnd, approvalRequestId, rollbackToken, status).
- Domain: `environmentId String?`. DnsRecord: `providerRef String?`. SslCertificate: `challenge String?`, `lastError String?`.
- ApprovalRequest: `action String?`, `riskTier String?`, `bindingHash String?`, `expiresAt DateTime?`.
- Permission catalog additions: `project.database.manage`, `security.incident.manage`, `platform.approval.decide`, `platform.access.review`.

## Runbooks
See docs/runbooks: PLATFORM-RECOVERY.md, EMERGENCY-OWNER.md, BACKUP-RESTORE-OPERATIONS.md, INCIDENT-RESPONSE.md, SECURITY-TEST-PLAN.md. None was rehearsed.
