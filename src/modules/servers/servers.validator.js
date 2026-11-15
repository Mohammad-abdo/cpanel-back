import { z } from 'zod';

export const listServersQuerySchema = z
  .object({
    limit: z.coerce.number().int().min(1).max(100).default(20),
    cursor: z.string().uuid().optional(),
  })
  .strict();

export const serverIdParamsSchema = z
  .object({
    id: z.string().uuid(),
  })
  .strict();

export const createServerBodySchema = z
  .object({
    alias: z
      .string()
      .trim()
      .min(2)
      .max(80)
      .regex(/^[a-z0-9][a-z0-9-]*$/, 'lowercase letters, digits and dashes'),
    hostname: z.string().trim().max(255).optional(),
  })
  .strict();

export const fleetReadQuerySchema = z
  .object({ serverId: z.string().uuid().optional(), limit: z.coerce.number().int().min(1).max(1000).default(500) })
  .strict();

export const metricsQuerySchema = z
  .object({ hours: z.coerce.number().int().min(1).max(168).default(24) })
  .strict();
