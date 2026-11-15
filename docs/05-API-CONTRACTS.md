# Api Contracts

Status: requirements/specifications, not implemented capabilities. Source: required.md sections 11.

## 11. Backend API

Feature modules own controller/validator/service/routes; optional repositories/policies. apps/api/src/config/common/modules/jobs/sockets and prisma/schema/migrations/seed; apps/worker; apps/web/src/app/layouts/modules/components/hooks/services/store/theme/routes/assets; agents/ubuntu-agent; packages/shared-contracts/permission-catalog/event-schemas; infrastructure/tests/docs. Modules auth/users/teams/servers/projects/deployments/domains/certificates/databases/backups/operations/monitoring/logs/security/incidents/reports/audit/notifications. /api/v1: auth login/mfa/verify/logout; users/:id/activity; roles/grants/access-reviews; servers/:id/metrics/services; projects/:id/health/logs/errors/deployments; deployments/:id; operations/:id/cancel; approvals/:id/approve; domains/:id/dns-records; certificates/:id/renew; backup-policies/backups/restores; security/events/incidents; reports/:id/runs/team; audit/events; notifications/preferences. Operation flow session/MFA/CSRF->scope->risk/approval->PENDING_APPROVAL or QUEUED->Agent validation->execute->result/audit/activity->Socket update->health. operationId/correlationId/idempotencyKey required. Full DTO/OpenAPI remains planned.

## Generated OpenAPI document

`docs/openapi.json` (OpenAPI 3.1, generated, do not edit by hand) describes every `/api/v1` operation found in `apps/api/src/routes.js` and the `*.routes.js` files: path and query parameters and request bodies from the Zod validators (via `z.toJSONSchema`), the bearer or Agent security scheme, MFA and rate-limit markers (`x-requires-mfa`, `x-rate-limited`), and the error envelope `{error:{code,message,requestId}}`. Public operations (health, login, MFA verify, logout, agent enroll) have an empty security list. Response bodies are not modeled because no response DTOs exist in code.

Regenerate after any route or validator change: `node scripts/generate-openapi.mjs`. Suggested package.json script: `"openapi": "node scripts/generate-openapi.mjs"`.


