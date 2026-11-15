/**
 * Shared contracts (formerly the @nodeteam/shared-contracts workspace package).
 * Operation envelope: docs/06-AGENT-SPECIFICATION.md and docs/openapi.json (enqueueBodySchema).
 */
import { z } from 'zod';

export const RISK_LEVELS = Object.freeze(['low', 'medium', 'high', 'critical']);

export const operationEnvelopeSchema = z
  .object({
    operationId: z.string().uuid(),
    correlationId: z.string().uuid(),
    idempotencyKey: z.string().min(8).max(128),
    type: z.string().min(1).max(120),
    resourceType: z.string().min(1).max(80),
    resourceId: z.string().min(1).max(80),
    environmentId: z.string().uuid().nullable().optional(),
    riskLevel: z.enum(RISK_LEVELS),
    expiresAt: z.string().datetime(),
    initiatorId: z.string().uuid().nullable().optional(),
    approverId: z.string().uuid().nullable().optional(),
    payload: z.record(z.string(), z.unknown()).optional(),
  })
  .strict();

/** True when the operation's expiry is at or before `now` (or unparseable: fail closed). */
export function isOperationExpired(expiresAt, now = new Date()) {
  const t = new Date(expiresAt).getTime();
  if (Number.isNaN(t)) return true;
  return t <= new Date(now).getTime();
}
