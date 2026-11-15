import { z } from 'zod';

export const serverMetricsParamsSchema = z
  .object({
    id: z.string().uuid(),
  })
  .strict();

export const serverMetricsQuerySchema = z
  .object({
    from: z.string().datetime().optional(),
    to: z.string().datetime().optional(),
  })
  .strict();

export const fleetQuerySchema = z
  .object({ hours: z.coerce.number().int().min(1).max(168).default(24) })
  .strict();

export const listErrorsQuerySchema = z
  .object({
    projectId: z.string().uuid().optional(),
    limit: z.coerce.number().int().min(1).max(100).default(50),
  })
  .strict();

export const errorGroupIdParamsSchema = z.object({ id: z.string().uuid() }).strict();
