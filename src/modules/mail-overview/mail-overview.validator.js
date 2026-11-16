import { z } from 'zod';

export const mailOverviewQuerySchema = z.object({}).strict();

export const mailAuditQuerySchema = z
  .object({
    limit: z.coerce.number().int().min(1).max(100).default(20),
    serverId: z.string().uuid().optional(),
    domainId: z.string().uuid().optional(),
  })
  .strict();

export const mailHealthSummaryQuerySchema = z.object({}).strict();
