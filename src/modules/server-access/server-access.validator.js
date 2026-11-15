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
