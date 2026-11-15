# NodeTeam Control implementation plan

Follow required.md section15. No scope/stack/phase/dependency changes without explicit user approval.

## 00 - Discovery & Technical Foundation

- [TASK-001](TASKS/TASK-001.md): Ubuntu inventory and security recovery baseline.
- [TASK-002](TASKS/TASK-002.md): Prisma MySQL API and Agent contracts.
- [TASK-003](TASKS/TASK-003.md): NodeTeam design system and screen inventory.

## 01 - Core Platform & Authentication

- [TASK-004](TASKS/TASK-004.md): API Web Worker Prisma MySQL foundation.
- [TASK-005](TASKS/TASK-005.md): Sessions MFA login and Owner protection.
- [TASK-006](TASKS/TASK-006.md): Resource permissions and team management.
- [TASK-007](TASKS/TASK-007.md): Audit infrastructure and activity events.

## 02 - Server Agents & Monitoring

- [TASK-008](TASKS/TASK-008.md): Agent enrollment mTLS and revocation.
- [TASK-009](TASKS/TASK-009.md): Read-only services processes and ports.
- [TASK-010](TASKS/TASK-010.md): Server monitoring dashboard.

## 03 - Project & Deployment Management

- [TASK-017](TASKS/TASK-017.md): Operation queue and approval workflow.
- [TASK-018](TASKS/TASK-018.md): Project discovery Git runtime and deployment.
- [TASK-019](TASKS/TASK-019.md): Deployment health checks and rollback.

## 04 - Observability & Project Logs

- [TASK-011](TASKS/TASK-011.md): Loki project log ingestion and redaction.
- [TASK-012](TASKS/TASK-012.md): Scoped log search live UI and export.
- [TASK-013](TASKS/TASK-013.md): Error groups and alert lifecycle.

## 05 - Team Intelligence & Reporting

- [TASK-014](TASKS/TASK-014.md): Member profile timeline and identity mapping.
- [TASK-015](TASKS/TASK-015.md): Team and project reports with event lineage.
- [TASK-016](TASKS/TASK-016.md): Scheduled PDF Excel and weekly monthly summaries.

## 06 - Domains SSL & Database Management

- [TASK-020](TASKS/TASK-020.md): Virtual hosts domains and DNS.
- [TASK-021](TASKS/TASK-021.md): SSL issue renewal and expiry.
- [TASK-022](TASKS/TASK-022.md): Managed project databases and scoped access.

## 07 - Backup & Disaster Recovery

- [TASK-023](TASKS/TASK-023.md): Consistent encrypted project database configuration backups.
- [TASK-024](TASKS/TASK-024.md): Offsite retention and artifact verification.
- [TASK-025](TASKS/TASK-025.md): Restore points isolated recovery and approval.

## 08 - Advanced Security & Operations

- [TASK-026](TASKS/TASK-026.md): Wazuh Security Center integration.
- [TASK-027](TASKS/TASK-027.md): Incident lifecycle evidence and ownership.
- [TASK-028](TASKS/TASK-028.md): Firewall maintenance and access reviews.

## 09 - Multi-Server & Production Hardening

- [TASK-029](TASKS/TASK-029.md): Multi-VPS scale and connection resilience.
- [TASK-030](TASKS/TASK-030.md): Security testing platform recovery and emergency Owner.
- [TASK-031](TASKS/TASK-031.md): Release acceptance and operational handover.

[Registry](TASK-BACKLOG.md) | [Traceability](REQUIREMENTS-TRACEABILITY.md). Read-only rollout is a safety gate, not permission to reorder phases. Inventory remains incomplete; documentation correction does not pass discovery. TASK-032 is historical, not an exception.

## 10 - Owner operations extensions (added 2026-11-15)

Added at the Owner's request; built before phase 09 by the Owner's choice.

- [TASK-033](TASKS/TASK-033.md): Management home with shortcuts.
- [TASK-034](TASKS/TASK-034.md): Create a database when adding a project.
- [TASK-035](TASKS/TASK-035.md): Add server by SSH host and password.
- [TASK-036](TASKS/TASK-036.md): Server file manager and web terminal.
- [TASK-037](TASKS/TASK-037.md): Project environments, environment variables and more project types.
- [TASK-038](TASKS/TASK-038.md): Server details page with full control.
- [TASK-039](TASKS/TASK-039.md): cPanel-style home page.
