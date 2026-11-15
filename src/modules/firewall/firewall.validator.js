import { z } from 'zod';

export const historyQuerySchema = z
  .object({ serverId: z.string().uuid().optional(), limit: z.coerce.number().int().min(1).max(200).default(50) })
  .strict();

export const serverParamsSchema = z.object({ serverId: z.string().uuid() }).strict();

const change = z
  .object({
    op: z.enum(['allow', 'deny', 'delete']),
    port: z.number().int().min(1).max(65535),
    proto: z.enum(['tcp', 'udp']).default('tcp'),
    source: z.string().max(64).regex(/^(any|\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?)$/, 'Invalid source'),
    comment: z.string().max(120).optional(),
  })
  .strict();

export const previewBodySchema = z.object({ changes: z.array(change).min(1).max(20) }).strict();

export const applyBodySchema = z
  .object({
    changes: z.array(change).min(1).max(20),
    windowStart: z.string().datetime(),
    windowEnd: z.string().datetime(),
    reason: z.string().min(5).max(500).optional(),
    rollbackNote: z.string().min(5).max(500).optional(),
    approvalId: z.string().uuid().optional(),
  })
  .strict();
