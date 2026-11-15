import { z } from 'zod';

export const listAuditQuerySchema = z
  .object({
    cursor: z.string().uuid().optional(),
    limit: z.coerce.number().int().min(1).max(100).default(20),
    resourceType: z.string().max(80).optional(),
    actorId: z.string().uuid().optional(),
    result: z.enum(['success', 'denied', 'failed', 'failure', 'error']).optional(),
    action: z.string().trim().max(120).optional(),
    from: z.string().datetime().optional(),
    to: z.string().datetime().optional(),
  })
  .strict();
