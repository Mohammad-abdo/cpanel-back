import { z } from 'zod';

export const listApprovalsQuerySchema = z
  .object({
    status: z.enum(['pending', 'approved', 'rejected', 'consumed']).optional(),
    limit: z.coerce.number().int().min(1).max(100).default(25),
  })
  .strict();

export const approvalIdParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const decideBodySchema = z
  .object({ decision: z.enum(['approve', 'reject']), note: z.string().max(500).optional() })
  .strict();

export const fleetProbeBodySchema = z.object({ serverIds: z.array(z.string().uuid()).min(1).max(500) }).strict();

export const fleetQuerySchema = z
  .object({ limit: z.coerce.number().int().min(1).max(500).default(100), cursor: z.string().uuid().optional() })
  .strict();

export const breakGlassBodySchema = z
  .object({ reason: z.string().min(10).max(500), recoveryCode: z.string().min(16).max(200), minutes: z.number().int().min(5).max(60).default(30) })
  .strict();

export const breakGlassEndBodySchema = z.object({ note: z.string().max(500).optional() }).strict();
