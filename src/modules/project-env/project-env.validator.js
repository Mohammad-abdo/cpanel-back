import { z } from 'zod';
import { ENV_KEY, MAX_VALUE, MAX_VARS } from './project-env.service.js';

export const envParamsSchema = z.object({ id: z.string().uuid(), envId: z.string().uuid() }).strict();
export const envKeyParamsSchema = envParamsSchema.extend({ key: z.string().regex(ENV_KEY) }).strict();
export const projectParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const setVarsBodySchema = z
  .object({
    vars: z
      .array(z.object({ key: z.string().regex(ENV_KEY, 'Invalid variable name'), value: z.string().max(MAX_VALUE), isSecret: z.boolean().default(false) }).strict())
      .min(1)
      .max(MAX_VARS),
  })
  .strict();

export const importBodySchema = z.object({ text: z.string().min(1).max(512 * 1024), markSecrets: z.boolean().default(true) }).strict();
export const writeServerBodySchema = z.object({ path: z.string().min(2).max(1024).regex(/^\//, 'Use an absolute path, e.g. /var/www/app/.env') }).strict();
export const pullServerBodySchema = z
  .object({
    /** Absolute path. When omitted, uses discoveredPath/.env on the project runtime. */
    path: z.string().min(2).max(1024).regex(/^\//, 'Use an absolute path').optional(),
    /** When true, upsert parsed keys into this environment after reading. */
    import: z.boolean().default(false),
    markSecrets: z.boolean().default(true),
  })
  .strict();
export const addEnvironmentBodySchema = z
  .object({ code: z.string().regex(/^[a-z][a-z0-9-]{0,31}$/, 'Use lowercase letters, numbers and dashes'), displayName: z.string().trim().min(1).max(80) })
  .strict();
