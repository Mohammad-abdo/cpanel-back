# Permissions Matrix

Status: requirements/specifications, not implemented capabilities. Source: required.md sections 7.

## 7. Permissions

Owner ultimate control; Infrastructure Admin allowed servers; DevOps allowed deployment/services; Team Lead assigned projects/team; Developer granted actions; Security Analyst security analysis; Auditor logs/reports/audit; Viewer selected reads. Only designated Owner; no Team Lead self-escalation/new Owner/scope widening. Action+resource type+resource ID+environment+conditions. Permissions: project.logs.read, project.deploy.create, project.restart.execute, project.env.metadata.read, project.secret.rotate, project.backup.create/restore, server.metrics.read, server.firewall.update, server.service.restart, domain.create, ssl.issue, team.member.invite, team.permission.assign, audit.logs.read, report.team.export. Staging grants do not imply production. Low: metrics; Medium: single-service restart/backup; High: production deploy/sensitive DNS-SSL; Critical: production restore/DB deletion/SSH-firewall. High/Critical approvals/reverification/reason/impact/rollback. Enforce backend and Agent, not hidden buttons.




## Role-permission matrix (seed definitions)

Source: `apps/api/src/modules/rbac/rbac.roles.js`; seeded by `apps/api/prisma/seed.js` (idempotent upserts).
Rules: environment-requiring permissions match only a role scoped to that exact environment (staging never implies production); `team.permission.assign` via a role works only within the role's own team; the Owner role is never granted through UserRole (Owner is the user owner flag); Developer holds read basics only and needs explicit ResourceGrants for any other action.

| Role | Permissions |
|---|---|
| Owner | all (bypass) |
| Infrastructure Admin | server.metrics.read, server.firewall.update, server.service.restart, domain.create, ssl.issue, project.logs.read, project.restart.execute, project.backup.create, project.backup.restore, project.database.manage, project.configure |
| DevOps | project.deploy.create, project.restart.execute, project.logs.read, project.env.metadata.read, project.backup.create, project.configure, domain.create, ssl.issue, server.metrics.read |
| Team Lead | team.member.invite, team.permission.assign (own team only), report.team.export, project.logs.read, server.metrics.read, project.deploy.create, project.restart.execute |
| Developer | project.logs.read, project.env.metadata.read, server.metrics.read |
| Security Analyst | audit.logs.read, project.logs.read, server.metrics.read, security.incident.manage, platform.access.review, report.team.export |
| Auditor | audit.logs.read, project.logs.read, report.team.export, server.metrics.read |
| Viewer | server.metrics.read |
