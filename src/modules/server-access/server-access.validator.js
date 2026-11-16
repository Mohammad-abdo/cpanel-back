import { z } from 'zod';

const host = z
  .string()
  .trim()
  .min(1)
  .max(253)
  .regex(/^[A-Za-z0-9.:\-[\]]+$/, 'Host must be a hostname or IP address');
const alias = z
  .string()
  .trim()
  .min(2)
  .max(60)
  .regex(/^[a-z0-9][a-z0-9-]*$/, 'Use lowercase letters, numbers and dashes');
const remotePath = z.string().min(1).max(4096).refine((p) => !p.includes('\0'), 'Invalid path');

export const credentialBodySchema = z
  .object({
    host,
    port: z.number().int().min(1).max(65535).default(22),
    username: z.string().trim().min(1).max(64).regex(/^[A-Za-z0-9._-]+$/, 'Invalid username'),
    password: z.string().min(1).max(1024),
  })
  .strict();

export const addServerBodySchema = credentialBodySchema.extend({ alias }).strict();

export const serverIdParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const listQuerySchema = z.object({ path: z.string().max(4096).optional() }).strict();
export const pathQuerySchema = z.object({ path: remotePath }).strict();
export const deleteQuerySchema = z
  .object({ path: remotePath, recursive: z.enum(['true', 'false']).optional().transform((v) => v === 'true') })
  .strict();

export const writeBodySchema = z.object({ path: remotePath, content: z.string().max(1024 * 1024) }).strict();
export const mkdirBodySchema = z.object({ path: remotePath }).strict();
export const renameBodySchema = z.object({ from: remotePath, to: remotePath }).strict();

export const serviceBodySchema = z
  .object({
    name: z.string().regex(/^[A-Za-z0-9@._-]{1,100}$/, 'Invalid service name'),
    action: z.enum(['start', 'stop', 'restart', 'reload', 'status', 'enable', 'disable']),
  })
  .strict();

/** Import selection after a scan. Empty arrays mean "skip that kind"; omit a key to import all of that kind from the latest scan payload embedded in the request. */
export const inventoryImportBodySchema = z
  .object({
    projects: z.array(z.string().min(1).max(300)).max(200).optional(),
    domains: z.array(z.string().min(1).max(253)).max(200).optional(),
    databases: z.array(z.enum(['mysql', 'postgres'])).max(4).optional(),
    /** When true, import every candidate returned by an inline scan (paths/names ignored). */
    importAll: z.boolean().optional(),
  })
  .strict();

export const dbEngineParamsSchema = z
  .object({
    id: z.string().uuid(),
    engine: z.enum(['mysql', 'postgres']),
  })
  .strict();

export const dbTablesQuerySchema = z
  .object({
    db: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/),
  })
  .strict();

export const dbTableQuerySchema = z
  .object({
    db: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/),
    table: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,63}$/),
    limit: z.coerce.number().int().min(1).max(200).optional(),
    offset: z.coerce.number().int().min(0).max(100000).optional(),
  })
  .strict();

export const dbQueryBodySchema = z
  .object({
    sql: z.string().min(1).max(20000),
    db: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/).optional(),
  })
  .strict();
