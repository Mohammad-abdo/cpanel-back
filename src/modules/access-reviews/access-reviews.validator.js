import { z } from 'zod';

export const reviewIdParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const startReviewBodySchema = z
  .object({ periodStart: z.string().datetime(), periodEnd: z.string().datetime(), subjectUserId: z.string().uuid().optional() })
  .strict();

export const decideBodySchema = z
  .object({
    decisions: z
      .array(z.object({ grantId: z.string().uuid(), decision: z.enum(['keep', 'revoke']), note: z.string().max(300).optional() }).strict())
      .min(1)
      .max(200),
  })
  .strict();

export const listReviewsQuerySchema = z
  .object({ status: z.enum(['open', 'completed']).optional(), limit: z.coerce.number().int().min(1).max(100).default(20) })
  .strict();
