# System Architecture

Status: requirements/specifications, not implemented capabilities. Source: required.md sections 1,2,11.

## 1. Technology stack

Node.js LTS, Express JavaScript, Prisma ORM, MySQL8 metadata. React/Vite/JSX, MUI9, Tailwind, Motion (motion/react), Axios/TanStack Query, Zustand, Socket.IO. BullMQ/Redis, Zod, sessions/MFA, OpenAPI. Independent Go Agent, Prometheus, Loki, Restic, Wazuh. Vitest/Supertest/Playwright. Verify version compatibility before installation.

## 2. Architecture

NodeTeam Control is a multi-VPS Infrastructure, DevOps and Team Operations Platform for Ubuntu production servers running Node/PM2, Laravel, Apache and MySQL/PostgreSQL/MongoDB/Redis workloads. Owner controls resources, identities, changes, outcomes, domains, certificates, backups and security. Modular monolith API with separate workers and agents. React displays scoped data; API owns policies/approvals/reports; Prisma/MySQL metadata; Redis queues; Loki raw logs; Prometheus metrics. Gateway uses mTLS/job validation/scoped operations/audit. No direct dashboard root access. Control-plane failure must not stop applications.

## 11. Backend API

Feature modules own controller/validator/service/routes; optional repositories/policies. apps/api/src/config/common/modules/jobs/sockets and prisma/schema/migrations/seed; apps/worker; apps/web/src/app/layouts/modules/components/hooks/services/store/theme/routes/assets; agents/ubuntu-agent; packages/shared-contracts/permission-catalog/event-schemas; infrastructure/tests/docs. Modules auth/users/teams/servers/projects/deployments/domains/certificates/databases/backups/operations/monitoring/logs/security/incidents/reports/audit/notifications. /api/v1: auth login/mfa/verify/logout; users/:id/activity; roles/grants/access-reviews; servers/:id/metrics/services; projects/:id/health/logs/errors/deployments; deployments/:id; operations/:id/cancel; approvals/:id/approve; domains/:id/dns-records; certificates/:id/renew; backup-policies/backups/restores; security/events/incidents; reports/:id/runs/team; audit/events; notifications/preferences. Operation flow session/MFA/CSRF->scope->risk/approval->PENDING_APPROVAL or QUEUED->Agent validation->execute->result/audit/activity->Socket update->health. operationId/correlationId/idempotencyKey required. Full DTO/OpenAPI remains planned.


