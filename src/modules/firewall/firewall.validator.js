import { z } from 'zod';
import { COMMENT_RE, SOURCE_RE, parseSource } from './firewall.ufw.js';

export const historyQuerySchema = z
  .object({ serverId: z.string().uuid().optional(), limit: z.coerce.number().int().min(1).max(200).default(50) })
  .strict();

export const serverParamsSchema = z.object({ serverId: z.string().uuid() }).strict();

const change = z
  .object({
    op: z.enum(['allow', 'deny', 'limit', 'delete']),
    action: z.enum(['allow', 'deny', 'limit']).optional(),
    port: z.number().int().min(1).max(65535),
    proto: z.enum(['tcp', 'udp']).default('tcp'),
    source: z.string().max(64).regex(SOURCE_RE, 'Invalid source').refine((v) => parseSource(v) !== null, 'Invalid source'),
    comment: z.string().regex(COMMENT_RE, 'Unsupported characters in comment').optional(),
  })
  .strict();

export const previewBodySchema = z.object({ changes: z.array(change).min(1).max(20), enable: z.boolean().optional() }).strict();

export const applyBodySchema = z
  .object({
    changes: z.array(change).min(1).max(20),
    enable: z.boolean().optional(),
    windowStart: z.string().datetime(),
    windowEnd: z.string().datetime(),
    reason: z.string().min(5).max(500).optional(),
    rollbackNote: z.string().min(5).max(500).optional(),
    approvalId: z.string().uuid().optional(),
  })
  .strict();
