# NodeTeam Control documentation

Multi-VPS infrastructure, DevOps and team operations: Ubuntu, Node/PM2/Laravel, project logs, member activity/reports, permissions/security, domains/SSL/databases/backups.

Required stack: Node/Express JavaScript and Prisma/MySQL8; React/Vite/JSX, MUI/Tailwind/Motion; Socket.IO; BullMQ/Redis; Go Agent; Prometheus/Loki; Restic; Wazuh. Each backend module owns controller/validator/service/routes.

## Start here

- [Plan](PLAN/MASTER-PLAN.md)
- [Task registry](PLAN/TASK-BACKLOG.md)
- [Requirement traceability](PLAN/REQUIREMENTS-TRACEABILITY.md)
- [Actual status](18-PROJECT-STATUS.md)

## Delivery specifications

- [01-PRD.md](01-PRD.md)
- [02-SRS.md](02-SRS.md)
- [03-SYSTEM-ARCHITECTURE.md](03-SYSTEM-ARCHITECTURE.md)
- [04-DATABASE-SCHEMA.md](04-DATABASE-SCHEMA.md)
- [05-API-CONTRACTS.md](05-API-CONTRACTS.md)
- [06-AGENT-SPECIFICATION.md](06-AGENT-SPECIFICATION.md)
- [07-PERMISSIONS-MATRIX.md](07-PERMISSIONS-MATRIX.md)
- [08-UI-SCREENS.md](08-UI-SCREENS.md)
- [09-LOGGING-AND-MONITORING.md](09-LOGGING-AND-MONITORING.md)
- [10-TEAM-REPORTING.md](10-TEAM-REPORTING.md)
- [11-SECURITY-PLAN.md](11-SECURITY-PLAN.md)
- [12-BACKUP-RESTORE.md](12-BACKUP-RESTORE.md)
- [13-IMPLEMENTATION-ROADMAP.md](13-IMPLEMENTATION-ROADMAP.md)
- [14-TEST-PLAN.md](14-TEST-PLAN.md)
- [15-DEPLOYMENT-RUNBOOK.md](15-DEPLOYMENT-RUNBOOK.md)

## Sources and rules

- [English master requirements](sources/required.md)
- [Engineering workflow](sources/cursor.skill.md)
- [Inventory](discovery/INVENTORY.md)
- [Backend module boundaries](BACKEND-MODULES.md)
- [Decisions](DECISIONS.md)

All documentation is English-only. Product Arabic/English localization and RTL/LTR remain requirements. Current implementation is an early health API scaffold; specifications do not imply completed features. English source copies are normalized translations, not byte-identical originals. Original attachments remain in conversation history.
