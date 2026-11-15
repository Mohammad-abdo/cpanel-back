import { z } from 'zod';

const base = {
  windowMinutes: z.number().int().min(1).max(1440),
  environmentId: z.string().uuid().optional(),
  escalateAfterMinutes: z.number().int().min(1).max(1440).default(30),
};

const thresholdSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('error_count'), threshold: z.number().int().min(1).max(100000), ...base }).strict(),
  z
    .object({
      kind: z.literal('intermittent'),
      buckets: z.number().int().min(2).max(60),
      minBuckets: z.number().int().min(2).max(60),
      ...base,
    })
    .strict()
    .refine((v) => v.minBuckets <= v.buckets, { message: 'minBuckets cannot exceed buckets' }),
  z.object({ kind: z.literal('no_data'), ...base }).strict(),
]);

export const createRuleBodySchema = z
  .object({
    projectId: z.string().uuid(),
    severity: z.enum(['info', 'warning', 'critical']),
    threshold: thresholdSchema,
  })
  .strict();

export const listRulesQuerySchema = z.object({ projectId: z.string().uuid() }).strict();

export const listAlertsQuerySchema = z
  .object({
    projectId: z.string().uuid(),
    environmentId: z.string().uuid().optional(),
    status: z.enum(['firing', 'acknowledged', 'escalated', 'resolved']).optional(),
  })
  .strict();

export const alertIdParamsSchema = z.object({ id: z.string().uuid() }).strict();
export const ruleIdParamsSchema = z.object({ id: z.string().uuid() }).strict();
export const noteBodySchema = z.object({ note: z.string().max(300).optional() }).strict();

export const compareParamsSchema = z.object({ id: z.string().uuid() }).strict();
export const compareQuerySchema = z
  .object({ windowMinutes: z.coerce.number().int().min(5).max(720).default(30) })
  .strict();
