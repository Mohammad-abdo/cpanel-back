import { z } from 'zod';

const optionalInt = z.preprocess(
  (v) => (v === '' || v === null || v === undefined ? undefined : Number(v)),
  z.number().int().positive().optional(),
);

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
  })
  .strict();