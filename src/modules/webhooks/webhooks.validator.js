import { z } from 'zod';
import { HOOK_TOKEN_PATTERN } from './webhooks.crypto.js';

const envCode = z.string().regex(/^[a-z0-9][a-z0-9_-]{0,39}$/);
const branchName = z.string().regex(/^(?!-)(?!.*\.\.)[A-Za-z0-9._/-]{1,100}$/);
const branchMap = z.record(branchName, envCode).refine((m) => Object.keys(m).length <= 30);

export const projectIdParamsSchema = z.object({ id: z.string().uuid() }).strict();
export const hookParamsSchema = z.object({ id: z.string().uuid(), hookId: z.string().uuid() }).strict();
export const hookTokenParamsSchema = z.object({ token: z.string().regex(HOOK_TOKEN_PATTERN) }).strict();

export const createHookBodySchema = z
  .object({ environmentId: z.string().uuid(), label: z.string().trim().min(1).max(80) })
  .strict();

/** Optional body on the public hook call. Anything else is rejected. */
export const triggerHookBodySchema = z.preprocess(
  (v) => v ?? {},
  z.object({ commitSha: z.string().regex(/^[0-9a-f]{7,40}$/).optional(), branch: branchName.optional() }).strict(),
);

const deploySettings = z
  .object({
    basePath: z.string().max(220).optional(),
    pm2App: z.string().max(100).optional(),
    keepReleases: z.number().int().min(2).max(20).optional(),
    outputDir: z.string().max(100).nullable().optional(),
    startFile: z.string().max(100).nullable().optional(),
    healthUrl: z.string().max(200).nullable().optional(),
    healthTimeoutSec: z.number().int().min(3).max(120).optional(),
    installCommand: z.string().max(160).nullable().optional(),
    buildCommand: z.string().max(160).nullable().optional(),
    static: z.boolean().optional(),
    framework: z.string().max(40).nullable().optional(),
    autoDetect: z.boolean().optional(),
  })
  .strict();

export const updateSettingsBodySchema = z
  .object({
    repository: z.object({ remoteUrl: z.string().max(300), defaultBranch: branchName.optional() }).strict().optional(),
    webhook: z
      .object({ enabled: z.boolean().optional(), branchMap: branchMap.optional(), prMap: branchMap.optional(), rotateSecret: z.boolean().optional() })
      .strict()
      .optional(),
    deploy: deploySettings.optional(),
    /** Needed only when a build/install command is outside the allowlist (High risk, separate approver). */
    approval: z
      .object({ approvalId: z.string().uuid().optional(), reason: z.string().max(500).optional(), rollbackPlan: z.string().max(500).optional() })
      .strict()
      .optional(),
  })
  .strict();
