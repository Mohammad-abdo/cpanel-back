import { z } from 'zod';

export const MAX_RANGE_DAYS = 180;

export const projectReportParamsSchema = z.object({ id: z.string().uuid() }).strict();

const isoDate = z.string().refine((v) => !Number.isNaN(Date.parse(v)), 'Invalid date');

const rangeFields = {
  from: isoDate.optional(),
  to: isoDate.optional(),
  env: z.string().min(1).max(64).optional(),
  granularity: z.enum(['day', 'week']).default('day'),
  compare: z
    .enum(['true', 'false'])
    .default('true')
    .transform((v) => v === 'true'),
};

export const projectReportQuerySchema = z
  .object({
    ...rangeFields,
    timelinePage: z.coerce.number().int().min(1).max(1000).default(1),
    timelineLimit: z.coerce.number().int().min(1).max(200).default(50),
    timelineType: z.string().min(1).max(32).optional(),
  })
  .strict();

export const projectReportExportQuerySchema = z
  .object({
    ...rangeFields,
    format: z.enum(['csv', 'json']).default('json'),
    section: z
      .enum(['summary', 'daily', 'deployments', 'incidents', 'errors', 'audit', 'timeline', 'recommendations'])
      .default('summary'),
  })
  .strict();

export const projectsOverviewQuerySchema = z
  .object({
    days: z.coerce.number().int().min(1).max(MAX_RANGE_DAYS).default(30),
    limit: z.coerce.number().int().min(1).max(100).default(50),
  })
  .strict();
