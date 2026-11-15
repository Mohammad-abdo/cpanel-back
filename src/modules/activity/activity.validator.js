import { z } from 'zod';

export const myTimelineQuerySchema = z
  .object({
    from: z.string().datetime().optional(),
    to: z.string().datetime().optional(),
    category: z
      .enum(['deployment', 'operation', 'approval', 'config', 'access', 'denial', 'incident', 'security', 'audit'])
      .optional(),
    limit: z.coerce.number().int().min(1).max(200).default(50),
  })
  .strict();

export const projectTimelineQuerySchema = z
  .object({
    projectId: z.string().uuid(),
    from: z.string().datetime().optional(),
    to: z.string().datetime().optional(),
    category: z
      .enum(['deployment', 'operation', 'approval', 'config', 'access', 'denial', 'incident', 'security', 'audit'])
      .optional(),
    limit: z.coerce.number().int().min(1).max(500).default(100),
  })
  .strict();
