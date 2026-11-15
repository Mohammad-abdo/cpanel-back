import { z } from 'zod';

export const memberIdParamsSchema = z.object({ userId: z.string().uuid() }).strict();

export const timelineQuerySchema = z
  .object({
    from: z.string().datetime().optional(),
    to: z.string().datetime().optional(),
    category: z
      .enum(['deployment', 'operation', 'approval', 'config', 'access', 'denial', 'incident', 'security', 'audit'])
      .optional(),
    limit: z.coerce.number().int().min(1).max(500).default(100),
  })
  .strict();

export const analyticsQuerySchema = z
  .object({ from: z.string().datetime().optional(), to: z.string().datetime().optional() })
  .strict();

export const unattributedQuerySchema = z
  .object({
    from: z.string().datetime().optional(),
    to: z.string().datetime().optional(),
    limit: z.coerce.number().int().min(1).max(500).default(100),
  })
  .strict();

export const mapIdentityBodySchema = z
  .object({
    provider: z.enum(['ssh', 'github']),
    externalId: z.string().min(1).max(200),
    userId: z.string().uuid(),
  })
  .strict();

export const identityIdParamsSchema = z.object({ id: z.string().uuid() }).strict();
