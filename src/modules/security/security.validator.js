import { z } from 'zod';

export const listIncidentsQuerySchema = z
  .object({
    status: z.string().max(40).optional(),
    limit: z.coerce.number().int().min(1).max(100).default(20),
  })
  .strict();

export const listEventsQuerySchema = z
  .object({
    serverId: z.string().uuid().optional(),
    severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
    category: z.string().max(40).optional(),
    limit: z.coerce.number().int().min(1).max(200).default(50),
  })
  .strict();

export const syncBodySchema = z.object({ sinceMinutes: z.number().int().min(1).max(10080).default(60) }).strict();
