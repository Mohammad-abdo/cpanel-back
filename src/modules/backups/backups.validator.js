import { z } from 'zod';

export const KINDS = ['db', 'config', 'uploads'];

export const listPoliciesQuerySchema = z
  .object({ projectId: z.string().uuid().optional(), limit: z.coerce.number().int().min(1).max(100).default(20) })
  .strict();

export const policyIdParamsSchema = z.object({ id: z.string().uuid() }).strict();
export const runIdParamsSchema = z.object({ id: z.string().uuid() }).strict();
export const artifactIdParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const createPolicyBodySchema = z
  .object({
    projectId: z.string().uuid(),
    environmentId: z.string().uuid(),
    frequency: z.enum(['hourly', 'daily', 'weekly']),
    retentionDays: z.number().int().min(7).max(3650),
    encryption: z.literal('aes-256-gcm').default('aes-256-gcm'),
    destinationCategory: z.literal('offsite').default('offsite'),
    rpoMinutes: z.number().int().min(5).max(10080),
    rtoMinutes: z.number().int().min(5).max(10080),
  })
  .strict();

export const runBackupBodySchema = z
  .object({
    environmentId: z.string().uuid(),
    kinds: z.array(z.enum(KINDS)).min(1).default(['db', 'config']),
    trigger: z.enum(['manual', 'scheduled', 'pre-deploy']).default('manual'),
  })
  .strict();

export const listRunsQuerySchema = z
  .object({ policyId: z.string().uuid().optional(), limit: z.coerce.number().int().min(1).max(100).default(20) })
  .strict();

export const retentionBodySchema = z
  .object({
    environmentId: z.string().uuid(),
    reason: z.string().min(5).max(500).optional(),
    rollbackNote: z.string().min(5).max(500).optional(),
    approvalId: z.string().uuid().optional(),
  })
  .strict();

export const verifyBodySchema = z.object({ environmentId: z.string().uuid().optional() }).strict();
