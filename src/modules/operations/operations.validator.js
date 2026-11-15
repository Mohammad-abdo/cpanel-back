import { operationEnvelopeSchema } from '@nodeteam/shared-contracts';
import { z } from 'zod';

export const enqueueBodySchema = operationEnvelopeSchema;

export const operationIdParamsSchema = z
  .object({
    id: z.string().uuid(),
  })
  .strict();

export const decisionBodySchema = z
  .object({
    reason: z.string().min(3).max(500),
    rollbackPlan: z.string().max(1000).optional(),
  })
  .strict();

export const listApprovalsQuerySchema = z
  .object({
    status: z.enum(['PENDING', 'APPROVED', 'DENIED', 'EXPIRED']).default('PENDING'),
    limit: z.coerce.number().int().min(1).max(100).default(50),
  })
  .strict();
