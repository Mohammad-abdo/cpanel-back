import { z } from 'zod';
import { REPORT_TYPES } from './reports.metrics.js';

export const listReportsQuerySchema = z
  .object({
    limit: z.coerce.number().int().min(1).max(100).default(20),
  })
  .strict();

const FORMATS = ['csv', 'json', 'pdf', 'xlsx'];
const scope = {
  type: z.enum(REPORT_TYPES),
  projectId: z.string().uuid().optional(),
  userId: z.string().uuid().optional(),
};

export const previewQuerySchema = z
  .object({ ...scope, from: z.string().datetime(), to: z.string().datetime() })
  .strict();

export const createRunBodySchema = z
  .object({
    ...scope,
    from: z.string().datetime(),
    to: z.string().datetime(),
    formats: z.array(z.enum(FORMATS)).min(1).max(4).default(['csv']),
  })
  .strict();

export const idParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const createScheduleBodySchema = z
  .object({
    ...scope,
    period: z.enum(['weekly', 'monthly']),
    cron: z.string().min(9).max(40),
    recipients: z.array(z.string().uuid()).min(1).max(50),
    formats: z.array(z.enum(FORMATS)).min(1).max(4).default(['csv']),
  })
  .strict();

export const scheduleEnabledBodySchema = z.object({ enabled: z.boolean() }).strict();

export const createDefinitionBodySchema = z
  .object({
    name: z.string().trim().min(3).max(80),
    kind: z.enum(REPORT_TYPES),
    projectId: z.string().uuid().optional(),
    paramsJson: z
      .object({ userId: z.string().uuid().optional(), formats: z.array(z.enum(FORMATS)).min(1).max(4).optional() })
      .strict()
      .default({}),
  })
  .strict()
  .superRefine((v, ctx) => {
    if (v.kind === 'individual-activity' && !v.paramsJson.userId) {
      ctx.addIssue({ code: 'custom', path: ['paramsJson', 'userId'], message: 'userId is required for individual reports' });
    }
    if (v.kind !== 'individual-activity' && (!v.projectId || v.paramsJson.userId)) {
      ctx.addIssue({ code: 'custom', path: [v.projectId ? 'paramsJson' : 'projectId'], message: 'projectId is required and userId is not allowed for this report kind' });
    }
  });
