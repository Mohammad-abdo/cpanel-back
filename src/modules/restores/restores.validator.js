import { z } from 'zod';

export const restoreIdParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const listRestorePointsQuerySchema = z
  .object({ projectId: z.string().uuid(), limit: z.coerce.number().int().min(1).max(100).default(20) })
  .strict();

export const requestRestoreBodySchema = z
  .object({
    artifactId: z.string().uuid(),
    mode: z.enum(['isolated', 'inplace']).default('isolated'),
    targetEnvironmentId: z.string().uuid(),
    reason: z.string().min(5).max(500),
    rollbackNote: z.string().min(5).max(500),
  })
  .strict();

export const executeRestoreBodySchema = z.object({ environmentId: z.string().uuid() }).strict();
