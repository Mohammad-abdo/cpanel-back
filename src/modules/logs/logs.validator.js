import { z } from 'zod';

export const LOG_KINDS = ['application', 'runtime', 'web', 'database', 'deployment', 'jobs', 'security', 'audit'];
export const LOG_LEVELS = ['debug', 'info', 'warn', 'error', 'fatal'];

export const listLogSourcesQuerySchema = z
  .object({
    projectId: z.string().uuid().optional(),
    limit: z.coerce.number().int().min(1).max(100).default(20),
  })
  .strict();

export const registerSourceBodySchema = z
  .object({
    projectId: z.string().uuid().optional(),
    serverId: z.string().uuid().optional(),
    environmentId: z.string().uuid().optional(),
    kind: z.enum(LOG_KINDS),
  })
  .strict()
  .refine((v) => v.projectId || v.serverId, { message: 'projectId or serverId required' });

export const sourceIdParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const ingestBodySchema = z
  .object({
    sourceId: z.string().uuid(),
    entries: z
      .array(
        z
          .object({
            timestamp: z.string().datetime().optional(),
            level: z.enum(LOG_LEVELS).default('info'),
            message: z.string().min(1).max(20000),
            stack: z.string().max(40000).optional(),
            requestId: z.string().max(128).optional(),
            traceId: z.string().max(128).optional(),
            deploymentId: z.string().uuid().optional(),
            fields: z.record(z.string(), z.unknown()).optional(),
          })
          .strict(),
      )
      .min(1)
      .max(500),
  })
  .strict();

const filterShape = {
  projectId: z.string().uuid(),
  environmentId: z.string().uuid().optional(),
  kind: z.enum(LOG_KINDS).optional(),
  level: z.enum(LOG_LEVELS).optional(),
  minLevel: z.enum(LOG_LEVELS).optional(),
  requestId: z.string().max(128).optional(),
  traceId: z.string().max(128).optional(),
  deploymentId: z.string().uuid().optional(),
  from: z.string().datetime().optional(),
  to: z.string().datetime().optional(),
  q: z.string().max(200).optional(),
};

export const searchLogsQuerySchema = z
  .object({
    ...filterShape,
    limit: z.coerce.number().int().min(1).max(500).default(100),
    beforeSeq: z.coerce.number().int().min(0).optional(),
  })
  .strict();

export const exportLogsQuerySchema = z
  .object({ ...filterShape, format: z.enum(['csv', 'json']).default('csv'), limit: z.coerce.number().int().min(1).max(5000).default(1000) })
  .strict();

export const streamLogsQuerySchema = z.object({ ...filterShape, lastEventId: z.coerce.number().int().min(0).optional() }).strict();

export const createBookmarkBodySchema = z
  .object({
    name: z.string().min(1).max(120),
    projectId: z.string().uuid(),
    query: z.object(filterShape).partial({ projectId: true }).strict().optional(),
  })
  .strict();

export const bookmarkIdParamsSchema = z.object({ id: z.string().uuid() }).strict();
