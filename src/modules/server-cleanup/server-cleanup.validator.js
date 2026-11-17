import { z } from 'zod';
import { CLEANUP_TASKS } from './server-cleanup.scripts.js';

export const serverParamsSchema = z.object({ serverId: z.string().uuid() }).strict();
const taskList = z.array(z.enum(Object.keys(CLEANUP_TASKS))).min(1).max(Object.keys(CLEANUP_TASKS).length).refine((a) => new Set(a).size === a.length, 'Duplicate tasks');

export const previewBodySchema = z.object({ tasks: taskList }).strict();
export const applyBodySchema = z
  .object({
    tasks: taskList,
    reason: z.string().min(5).max(500).optional(),
    rollbackNote: z.string().min(5).max(500).optional(),
    approvalId: z.string().uuid().optional(),
  })
  .strict();
