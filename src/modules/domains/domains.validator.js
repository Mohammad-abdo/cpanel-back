import { z } from 'zod';

const HOSTNAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const hostname = z.string().trim().toLowerCase().regex(HOSTNAME, 'Invalid hostname');

export const listDomainsQuerySchema = z
  .object({
    projectId: z.string().uuid().optional(),
    serverId: z.string().uuid().optional(),
    limit: z.coerce.number().int().min(1).max(500).default(50),
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
    /** Cloudflare only: route through the proxy (A/AAAA/CNAME). Ignored by other providers. */
    proxied: z.boolean().optional(),
    environmentId: z.string().uuid(),
    ...approvalFields,
  })
  .strict();

export const domainConfBodySchema = z
  .object({
    content: z.string().max(1024 * 1024),
  })
  .strict();

export const caddyBodySchema = z
  .object({
    upstreamPort: z.number().int().min(1).max(65535),
    wwwRedirect: z.boolean().default(false),
    environmentId: z.string().uuid(),
  })
  .strict();

export const applyCaddyBodySchema = caddyBodySchema.extend(approvalFields).strict();

export const detectWebserverBodySchema = z.object({ environmentId: z.string().uuid() }).strict();
