import { z } from 'zod';

export const serverIdParamsSchema = z.object({ serverId: z.string().uuid() }).strict();

export const putSettingsBodySchema = z
  .object({
    enabled: z.boolean(),
    includeMysql: z.boolean(),
    includePostgres: z.boolean(),
    includeFiles: z.boolean(),
    filesPath: z.string().trim().max(512).nullable().optional(),
    retainCount: z.number().int().min(1).max(365),
    scheduleCron: z.string().trim().max(64).nullable().optional(),
  })
  .strict();