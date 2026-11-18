import { z } from 'zod';

const optionalInt = z.preprocess(
  (v) => (v === '' || v === null || v === undefined ? undefined : Number(v)),
  z.number().int().positive().optional(),
);

const approval = z.object({ approvalId: z.string().uuid().optional(), reason: z.string().trim().max(500).optional(), rollbackPlan: z.string().trim().max(500).optional() }).strict();
const repoName = /^[A-Za-z0-9_.-]{1,100}$/;
const page = z.preprocess((v) => (v === undefined || v === '' ? undefined : Number(v)), z.number().int().min(1).max(1000).optional());

export const upsertGitHubAppBodySchema = z
  .object({
    appId: optionalInt,
    clientId: z.string().trim().max(64).optional(),
    slug: z
      .string()
      .trim()
      .max(39)
      .regex(/^[a-z\d](?:[a-z\d-]*[a-z\d])?$/i, 'Invalid GitHub App slug')
      .optional(),
    installationId: z.string().trim().max(32).regex(/^\d+$/, 'Installation id must be numeric').optional(),
    /** PEM text; only sent on rotate. Never returned. */
    privateKey: z.string().min(100).max(20000).optional(),
    webhookSecret: z.string().min(16).max(256).optional(),
    publicBaseUrl: z.string().trim().url().max(200).optional(),
  })
  .strict();

export const approvalBodySchema = z.object({ approval: approval.optional() }).strict();

export const callbackQuerySchema = z.object({ code: z.string().regex(/^[A-Za-z0-9_-]{8,128}$/), state: z.string().min(20).max(300) }).passthrough();

export const installationParamsSchema = z.object({ installationId: z.string().regex(/^\d{1,20}$/) });
export const pageQuerySchema = z.object({ page }).passthrough();
export const installationQuerySchema = z.object({ page, installationId: z.string().regex(/^\d{1,20}$/).optional() }).passthrough();
export const branchesParamsSchema = z.object({ owner: z.string().regex(repoName), repo: z.string().regex(repoName) });
export const projectParamsSchema = z.object({ projectId: z.string().uuid() });

export const linkRepoBodySchema = z
  .object({
    repo: z.string().regex(/^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/, 'Repository must be owner/name'),
    installationId: z.string().regex(/^\d{1,20}$/).optional(),
    defaultBranch: z.string().trim().min(1).max(200).regex(/^[A-Za-z0-9._/-]+$/).optional(),
    branchMap: z.record(z.string().min(1).max(200), z.string().min(1).max(64)).optional(),
    autoDeploy: z.boolean().optional(),
  })
  .strict();
