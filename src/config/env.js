import { z } from 'zod';

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  HOST: z.string().trim().min(1).default('127.0.0.1'),
  PORT: z.coerce.number().int().min(1).max(65535).default(4000),
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
