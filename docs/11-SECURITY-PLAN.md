# Security Plan

Status: requirements/specifications, not implemented capabilities. Source: required.md sections 7,9,14.

## 7. Permissions

Owner ultimate control; Infrastructure Admin allowed servers; DevOps allowed deployment/services; Team Lead assigned projects/team; Developer granted actions; Security Analyst security analysis; Auditor logs/reports/audit; Viewer selected reads. Only designated Owner; no Team Lead self-escalation/new Owner/scope widening. Action+resource type+resource ID+environment+conditions. Permissions: project.logs.read, project.deploy.create, project.restart.execute, project.env.metadata.read, project.secret.rotate, project.backup.create/restore, server.metrics.read, server.firewall.update, server.service.restart, domain.create, ssl.issue, team.member.invite, team.permission.assign, audit.logs.read, report.team.export. Staging grants do not imply production. Low: metrics; Medium: single-service restart/backup; High: production deploy/sensitive DNS-SSL; Critical: production restore/DB deletion/SSH-firewall. High/Critical approvals/reverification/reason/impact/rollback. Enforce backend and Agent, not hidden buttons.

## 9. Security Center

SSH successes/failures/trends, sessions/users/sudo, firewall/ports/unexpected services, file integrity, updates, malware/suspicious processes, certificate expiry and scoped alerts. Incident: Detected->Triaged->Assigned->Investigating->Contained->Resolved->Closed. Evidence/events/severity/owner/actions/timestamps. No guarantee of total compromise detection; untrusted hosts require independent evidence, not Agent data alone.

## 14. Non-functional

Isolate control plane; MFA/least privilege/mTLS; encrypted secrets/redaction; bounded retries/idempotency/timeouts; independent audit; multiple servers/distributed workers; pagination/streaming; separate retention; offsite/restore drills; platform recovery/Owner emergency; unit/integration/E2E/security/restore tests. Dashboard outage cannot stop customers. Agent reconnect cannot replay stale jobs.


