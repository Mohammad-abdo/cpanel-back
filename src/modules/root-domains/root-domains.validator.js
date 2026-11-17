import { z } from 'zod';

const HOSTNAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const hostname = z.string().trim().toLowerCase().regex(HOSTNAME, 'Invalid hostname');

export const idParamsSchema = z.object({ id: z.string().uuid() }).strict();

const approvalFields = {
  reason: z.string().min(5).max(500).optional(),
  rollbackNote: z.string().min(5).max(500).optional(),
  approvalId: z.string().uuid().optional(),
};

/** The token is only ever accepted in a request body, never in a URL or query string. */
export const connectBodySchema = z
  .object({
    name: hostname,
    provider: z.enum(['cloudflare', 'simulated']).default('cloudflare'),
    apiToken: z.string().min(20).max(128).regex(/^[A-Za-z0-9_-]+$/, 'Invalid token format').optional(),
  })
  .strict()
  .refine((b) => b.provider === 'simulated' || Boolean(b.apiToken), { message: 'A Cloudflare API token is required' });

export const rotateTokenBodySchema = z.object({ apiToken: z.string().min(20).max(128).regex(/^[A-Za-z0-9_-]+$/) }).strict();

export const listRecordsQuerySchema = z
  .object({
    type: z.enum(['A', 'AAAA', 'CNAME', 'TXT']).optional(),
    name: z.string().trim().toLowerCase().max(253).optional(),
    page: z.coerce.number().int().min(1).max(100).default(1),
  })
  .strict();

export const recordBodySchema = z
  .object({
    op: z.enum(['upsert', 'remove']),
    type: z.enum(['A', 'AAAA', 'CNAME', 'TXT']),
    name: z.string().trim().toLowerCase().min(1).max(253),
    value: z.string().min(1).max(512),
    ttl: z.number().int().min(60).max(86400).default(300),
    proxied: z.boolean().default(false),
    ...approvalFields,
  })
  .strict();

export const wildcardBodySchema = z
  .object({
    serverId: z.string().uuid(),
    email: z.string().email().max(254).optional(),
    staging: z.boolean().default(false),
    propagationSeconds: z.number().int().min(10).max(600).default(30),
    ...approvalFields,
  })
  .strict();
