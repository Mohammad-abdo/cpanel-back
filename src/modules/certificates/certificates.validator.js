import { z } from 'zod';

export const listCertsQuerySchema = z
  .object({ domainId: z.string().uuid().optional(), limit: z.coerce.number().int().min(1).max(100).default(50) })
  .strict();

export const expiringQuerySchema = z.object({ days: z.coerce.number().int().min(1).max(365).default(30) }).strict();

export const domainParamsSchema = z.object({ domainId: z.string().uuid() }).strict();
export const certParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const issueBodySchema = z
  .object({
    environmentId: z.string().uuid(),
    challenge: z.enum(['http-01', 'dns-01']).default('http-01'),
    wildcard: z.boolean().default(false),
    reason: z.string().min(5).max(500).optional(),
    rollbackNote: z.string().min(5).max(500).optional(),
    approvalId: z.string().uuid().optional(),
  })
  .strict();

export const renewBodySchema = z.object({ environmentId: z.string().uuid(), force: z.boolean().default(false) }).strict();
