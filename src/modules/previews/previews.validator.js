import { z } from 'zod';

const envCode = z.string().regex(/^[a-z0-9][a-z0-9_-]{0,39}$/);
const envKey = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,99}$/);
const branchName = z.string().regex(/^(?!-)(?!.*\.\.)[A-Za-z0-9._/-]{1,100}$/);

export const projectParamsSchema = z.object({ id: z.string().uuid() }).strict();
export const previewParamsSchema = z.object({ id: z.string().uuid(), previewId: z.string().uuid() }).strict();

export const updateSettingsBodySchema = z
  .object({
    enabled: z.boolean().optional(),
    rootDomainId: z.string().uuid().nullable().optional(),
    sourceEnvCode: envCode.nullable().optional(),
    envKeys: z.array(envKey).max(50).optional(),
    portStart: z.number().int().min(1024).max(65535).optional(),
    portEnd: z.number().int().min(1024).max(65535).optional(),
    ttlDays: z.number().int().min(1).max(30).optional(),
    maxActive: z.number().int().min(1).max(20).optional(),
    basicAuth: z.boolean().optional(),
    dnsMode: z.enum(['per-pr', 'wildcard']).optional(),
    commentEnabled: z.boolean().optional(),
    /** GitHub token for PR comments. Stored encrypted, never returned. null removes it. */
    githubToken: z.string().regex(/^[A-Za-z0-9_]{20,255}$/).nullable().optional(),
  })
  .strict();

export const createBodySchema = z
  .object({
    prNumber: z.number().int().min(1).max(999999999),
    branch: branchName,
    commitSha: z.string().regex(/^[0-9a-f]{7,40}$/),
    approvalId: z.string().uuid().optional(),
  })
  .strict();

export const exposeBodySchema = z
  .object({
    approvalId: z.string().uuid().optional(),
    reason: z.string().min(5).max(500).optional(),
    rollbackNote: z.string().min(5).max(500).optional(),
  })
  .strict();

export const extendBodySchema = z.object({ days: z.number().int().min(1).max(30) }).strict();
