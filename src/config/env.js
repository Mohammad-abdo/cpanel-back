import { z } from 'zod';

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  HOST: z.string().trim().min(1).default('127.0.0.1'),
  PORT: z.coerce.number().int().min(1).max(65535).default(4000),
  /** TASK-037 webmail gateway (separate process from /api/v1). */
  WEBMAIL_HOST: z.string().trim().min(1).default('127.0.0.1'),
  WEBMAIL_PORT: z.coerce.number().int().min(1).max(65535).default(2096),
  WEBMAIL_PUBLIC_URL: z.string().trim().url().optional(),
  /** Lab only: allow IMAP/SMTP TLS with self-signed server certs. */
  WEBMAIL_TLS_INSECURE: z
    .string()
    .optional()
    .transform((v) => v === '1' || v === 'true'),
  DATABASE_URL: z.string().trim().min(1).optional(),
  REDIS_URL: z.string().trim().min(1).optional(),
  SESSION_SECRET: z.string().trim().min(16).optional(),
});

export function parseEnv(input = process.env) {
  const result = schema.safeParse(input);
  if (!result.success) {
    throw new Error(`Invalid environment fields: ${result.error.issues.map((i) => i.path.join('.')).join(', ')}`);
  }
  return result.data;
}
