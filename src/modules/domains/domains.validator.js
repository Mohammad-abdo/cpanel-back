import { z } from 'zod';

const HOSTNAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const hostname = z.string().trim().toLowerCase().regex(HOSTNAME, 'Invalid hostname');

export const listDomainsQuerySchema = z
  .object({
    projectId: z.string().uuid().optional(),
    limit: z.coerce.number().int().min(1).max(100).default(20),
  })
  .strict();

export const domainIdParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const createDomainBodySchema = z
  .object({
    name: hostname,
    projectId: z.string().uuid(),
    environmentId: z.string().uuid(),
    serverId: z.string().uuid().optional(),
  })
  .strict();

export const vhostBodySchema = z
  .object({
    upstreamPort: z.number().int().min(1).max(65535),
    webserver: z.enum(['nginx', 'apache']).default('nginx'),
    environmentId: z.string().uuid(),
  })
  .strict();

const approvalFields = {
  reason: z.string().min(5).max(500).optional(),
  rollbackNote: z.string().min(5).max(500).optional(),
  approvalId: z.string().uuid().optional(),
};

export const applyVhostBodySchema = vhostBodySchema.extend(approvalFields).strict();

export const dnsChangeBodySchema = z
  .object({
    op: z.enum(['upsert', 'remove']),
    type: z.enum(['A', 'AAAA', 'CNAME', 'TXT', 'MX']),
    name: z.string().trim().toLowerCase().min(1).max(253),
    value: z.string().min(1).max(512),
    ttl: z.number().int().min(60).max(86400).default(300),
    environmentId: z.string().uuid(),
    ...approvalFields,
  })
  .strict();
