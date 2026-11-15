import { z } from 'zod';

const approvalFields = {
  reason: z.string().min(5).max(500).optional(),
  rollbackNote: z.string().min(5).max(500).optional(),
  approvalId: z.string().uuid().optional(),
};

export const listDatabasesQuerySchema = z
  .object({ projectId: z.string().uuid().optional(), limit: z.coerce.number().int().min(1).max(100).default(50) })
  .strict();

export const databaseIdParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const createDatabaseBodySchema = z
  .object({
    projectId: z.string().uuid(),
    environmentId: z.string().uuid(),
    instanceId: z.string().uuid(),
    dbName: z.string().regex(/^[a-z][a-z0-9_]{2,40}$/, 'Invalid database name'),
    ...approvalFields,
  })
  .strict();

export const createUserBodySchema = z
  .object({
    environmentId: z.string().uuid(),
    username: z.string().regex(/^[a-z][a-z0-9_]{2,30}$/, 'Invalid username'),
    level: z.enum(['read', 'readwrite']),
    ...approvalFields,
  })
  .strict();

export const dropDatabaseBodySchema = z
  .object({
    environmentId: z.string().uuid(),
    confirmName: z.string().min(3).max(41),
    safetyBackupRunId: z.string().uuid(),
    ...approvalFields,
  })
  .strict();

export const createInstanceBodySchema = z
  .object({
    engine: z.enum(['mysql', 'postgres', 'mongodb', 'redis']),
    name: z.string().regex(/^[a-z][a-z0-9_-]{2,40}$/, 'Invalid instance name'),
    serverId: z.string().uuid().optional(),
    host: z.string().min(1).max(253).regex(/^[A-Za-z0-9._:-]+$/, 'Invalid host').optional(),
    port: z.coerce.number().int().min(1).max(65535).optional(),
    // Reference to a secret manager entry only (e.g. "vault:db/prod-admin"); never a password.
    adminSecretRef: z.string().min(3).max(190).regex(/^[A-Za-z0-9_./:@-]+$/, 'Invalid secret reference').optional(),
    ...approvalFields,
  })
  .strict();
