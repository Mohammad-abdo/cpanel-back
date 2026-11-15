# Canonical task registry

Source phase order is authoritative. Stable IDs preserve history; IDs are not execution order.

| ID | Phase | Capability | Dependency | Status |
|---|---|---|---|---|
| [TASK-001](TASKS/TASK-001.md) | 00 | Ubuntu inventory and security recovery baseline | None | IN_PROGRESS |
| [TASK-002](TASKS/TASK-002.md) | 00 | Prisma MySQL API and Agent contracts | TASK-001 | PLANNED |
| [TASK-003](TASKS/TASK-003.md) | 00 | NodeTeam design system and screen inventory | TASK-002 | PLANNED |
| [TASK-004](TASKS/TASK-004.md) | 01 | API Web Worker Prisma MySQL foundation | TASK-003 | PLANNED |
| [TASK-005](TASKS/TASK-005.md) | 01 | Sessions MFA login and Owner protection | TASK-004 | IN_REVIEW |
| [TASK-006](TASKS/TASK-006.md) | 01 | Resource permissions and team management | TASK-005 | IN_PROGRESS |
| [TASK-007](TASKS/TASK-007.md) | 01 | Audit infrastructure and activity events | TASK-006 | IN_PROGRESS |
| [TASK-008](TASKS/TASK-008.md) | 02 | Agent enrollment mTLS and revocation | TASK-007 | IN_PROGRESS |
| [TASK-009](TASKS/TASK-009.md) | 02 | Read-only services processes and ports | TASK-008 | IN_PROGRESS |
| [TASK-010](TASKS/TASK-010.md) | 02 | Server monitoring dashboard | TASK-009 | IN_PROGRESS |
| [TASK-017](TASKS/TASK-017.md) | 03 | Operation queue and approval workflow | TASK-010 | IN_PROGRESS |
| [TASK-018](TASKS/TASK-018.md) | 03 | Project discovery Git runtime and deployment | TASK-017 | IN_PROGRESS |
| [TASK-019](TASKS/TASK-019.md) | 03 | Deployment health checks and rollback | TASK-018 | IN_PROGRESS |
| [TASK-011](TASKS/TASK-011.md) | 04 | Loki project log ingestion and redaction | TASK-019 | IN_PROGRESS |
| [TASK-012](TASKS/TASK-012.md) | 04 | Scoped log search live UI and export | TASK-011 | IN_PROGRESS |
| [TASK-013](TASKS/TASK-013.md) | 04 | Error groups and alert lifecycle | TASK-012 | IN_REVIEW |
| [TASK-014](TASKS/TASK-014.md) | 05 | Member profile timeline and identity mapping | TASK-013 | IN_PROGRESS |
| [TASK-015](TASKS/TASK-015.md) | 05 | Team and project reports with event lineage | TASK-014 | IN_PROGRESS |
| [TASK-016](TASKS/TASK-016.md) | 05 | Scheduled PDF Excel and weekly monthly summaries | TASK-015 | IN_PROGRESS |
| [TASK-020](TASKS/TASK-020.md) | 06 | Virtual hosts domains and DNS | TASK-016 | IN_PROGRESS |
| [TASK-021](TASKS/TASK-021.md) | 06 | SSL issue renewal and expiry | TASK-020 | IN_PROGRESS |
| [TASK-022](TASKS/TASK-022.md) | 06 | Managed project databases and scoped access | TASK-021 | IN_PROGRESS |
| [TASK-023](TASKS/TASK-023.md) | 07 | Consistent encrypted project database configuration backups | TASK-022 | IN_PROGRESS |
| [TASK-024](TASKS/TASK-024.md) | 07 | Offsite retention and artifact verification | TASK-023 | IN_PROGRESS |
| [TASK-025](TASKS/TASK-025.md) | 07 | Restore points isolated recovery and approval | TASK-024 | IN_PROGRESS |
| [TASK-026](TASKS/TASK-026.md) | 08 | Wazuh Security Center integration | TASK-025 | IN_PROGRESS |
| [TASK-027](TASKS/TASK-027.md) | 08 | Incident lifecycle evidence and ownership | TASK-026 | IN_PROGRESS |
| [TASK-028](TASKS/TASK-028.md) | 08 | Firewall maintenance and access reviews | TASK-027 | IN_PROGRESS |
| [TASK-029](TASKS/TASK-029.md) | 09 | Multi-VPS scale and connection resilience | TASK-028 | IN_PROGRESS |
| [TASK-030](TASKS/TASK-030.md) | 09 | Security testing platform recovery and emergency Owner | TASK-029 | IN_PROGRESS |
| [TASK-031](TASKS/TASK-031.md) | 09 | Release acceptance and operational handover | TASK-030 | IN_PROGRESS |
| [TASK-032](TASKS/TASK-032.md) | Historical | Early backend scaffold | No prerequisite exception | IN_REVIEW |
