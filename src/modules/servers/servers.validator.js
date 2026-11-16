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

const aliasField = z
  .string()
  .trim()
  .min(2)
  .max(80)
  .regex(/^[a-z0-9][a-z0-9-]*$/, 'lowercase letters, digits and dashes');

export const createServerBodySchema = z
  .object({
    alias: aliasField,
    hostname: z.string().trim().max(255).optional(),
  })
  .strict();

export const updateServerBodySchema = z
  .object({
    alias: aliasField.optional(),
    hostname: z.string().trim().max(255).nullable().optional(),
  })
  .strict()
  .refine((v) => v.alias !== undefined || v.hostname !== undefined, { message: 'At least one field is required' });

export const archiveServerBodySchema = z
  .object({
    reason: z
      .string()
      .trim()
      .max(300)
      .optional()
      .transform((v) => (v && v.length >= 3 ? v : 'Removed from panel')),
  })
  .strict();

export const fleetReadQuerySchema = z
  .object({ serverId: z.string().uuid().optional(), limit: z.coerce.number().int().min(1).max(1000).default(500) })
  .strict();

/** GET /servers/runtimes takes no query parameters; unknown ones are rejected. */
export const runtimesQuerySchema = z.object({}).strict();

export const metricsQuerySchema = z
  .object({ hours: z.coerce.number().int().min(1).max(168).default(24) })
  .strict();
