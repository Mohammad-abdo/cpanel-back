import { z } from 'zod';
import { INTERVAL_SEC_VALUES, parseExpectedStatus } from './uptime.service.js';

const intervalSec = z
  .number()
  .int()
  .refine((n) => INTERVAL_SEC_VALUES.includes(n), 'intervalSec must be one of 30, 60, 120, 300, 600, 1800, 3600')
  .default(60);

const expectedStatus = z
  .string()
  .trim()
  .min(1)
  .max(50)
  .superRefine((v, ctx) => {
    try {
      parseExpectedStatus(v);
    } catch (e) {
      ctx.addIssue({ code: 'custom', message: (e instanceof Error ? e.message : 'Invalid expected status') });
    }
  });

const monitorFields = {
  name: z.string().trim().min(1).max(100),
  url: z.string().trim().min(1).max(2000).url(),
  method: z.enum(['GET', 'HEAD']).default('GET'),
  intervalSec,
  timeoutMs: z.number().int().min(1000).max(30000).default(10000),
  expectedStatus: expectedStatus.default('200-399'),
  keyword: z.string().trim().min(1).max(200).nullable().optional(),
  failureThreshold: z.number().int().min(1).max(10).default(2),
  enabled: z.boolean().default(true),
  projectId: z.string().uuid().nullable().optional(),
};

export const listUptimeQuerySchema = z
  .object({
    projectId: z.string().uuid().optional(),
  })
  .strict();

export const uptimeIdParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const createUptimeBodySchema = z
  .object(monitorFields)
  .strict()
  .superRefine((v, ctx) => {
    if (v.timeoutMs > v.intervalSec * 1000) {
      ctx.addIssue({ code: 'custom', path: ['timeoutMs'], message: 'Timeout must not exceed the check interval' });
    }
  });

export const updateUptimeBodySchema = z
  .object({
    name: monitorFields.name.optional(),
    url: monitorFields.url.optional(),
    method: monitorFields.method.optional(),
    intervalSec: intervalSec.optional(),
    timeoutMs: monitorFields.timeoutMs.optional(),
    expectedStatus: expectedStatus.optional(),
    keyword: monitorFields.keyword,
    failureThreshold: monitorFields.failureThreshold.optional(),
    enabled: z.boolean().optional(),
    projectId: monitorFields.projectId,
  })
  .strict()
  .refine((v) => Object.keys(v).length > 0, 'At least one field is required')
  .superRefine((v, ctx) => {
    if (v.timeoutMs != null && v.intervalSec != null && v.timeoutMs > v.intervalSec * 1000) {
      ctx.addIssue({ code: 'custom', path: ['timeoutMs'], message: 'Timeout must not exceed the check interval' });
    }
  });

export const emptyBodySchema = z.object({}).strict();