import { z } from 'zod';
import { CRON_COMMANDS, MAX_TIMEOUT_SEC, MIN_TIMEOUT_SEC, isSafeCustomCommand, isSafeWorkDir } from './cron.commands.js';
import { isValidCron } from './cron.parser.js';

export const projectParamsSchema = z.object({ projectId: z.string().uuid() }).strict();
export const jobParamsSchema = z.object({ projectId: z.string().uuid(), jobId: z.string().uuid() }).strict();
export const runsQuerySchema = z.object({ limit: z.coerce.number().int().min(1).max(100).default(25) }).strict();

const schedule = z.string().min(5).max(100).refine(isValidCron, 'Invalid 5-field cron schedule');
const workDir = z.string().refine(isSafeWorkDir, 'Working directory must be an absolute safe path outside system folders');
const approval = {
  reason: z.string().min(5).max(500).optional(),
  rollbackNote: z.string().min(5).max(500).optional(),
  approvalId: z.string().uuid().optional(),
};

export const createBodySchema = z
  .object({
    name: z.string().min(1).max(80),
    schedule,
    commandKey: z.enum(Object.keys(CRON_COMMANDS)).optional(),
    customCommand: z.string().refine(isSafeCustomCommand, 'Custom command must be one line, at most 500 characters').optional(),
    workDir,
    enabled: z.boolean().default(false),
    timeoutSec: z.number().int().min(MIN_TIMEOUT_SEC).max(MAX_TIMEOUT_SEC).default(300),
    ...approval,
  })
  .strict()
  .refine((b) => Boolean(b.commandKey) !== Boolean(b.customCommand), { message: 'Provide exactly one of commandKey or customCommand' });

export const updateBodySchema = z
  .object({
    name: z.string().min(1).max(80).optional(),
    schedule: schedule.optional(),
    commandKey: z.enum(Object.keys(CRON_COMMANDS)).optional(),
    customCommand: z.string().refine(isSafeCustomCommand, 'Custom command must be one line, at most 500 characters').optional(),
    workDir: workDir.optional(),
    enabled: z.boolean().optional(),
    timeoutSec: z.number().int().min(MIN_TIMEOUT_SEC).max(MAX_TIMEOUT_SEC).optional(),
    ...approval,
  })
  .strict()
  .refine((b) => !(b.commandKey && b.customCommand), { message: 'Provide only one of commandKey or customCommand' });

export const runBodySchema = z.object({ ...approval }).strict();
export const previewBodySchema = z.object({ schedule, count: z.number().int().min(1).max(10).default(5) }).strict();
