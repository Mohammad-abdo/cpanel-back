import { z } from 'zod';

export const enrollBodySchema = z
  .object({
    token: z.string().min(20).max(200),
    hostname: z.string().trim().max(255).optional(),
    capabilities: z.record(z.string(), z.unknown()).optional(),
  })
  .strict();

const pct = z.number().min(0).max(100);

export const reportBodySchema = z
  .object({
    capturedAt: z.string().datetime().optional(),
    cpuPercent: pct,
    memPercent: pct,
    swapPercent: pct.optional(),
    diskPercent: pct,
    load1: z.number().min(0).max(10000).optional(),
    uptimeSec: z.number().int().min(0).optional(),
    services: z
      .array(
        z
          .object({
            name: z.string().min(1).max(120),
            manager: z.enum(['systemd', 'pm2', 'apache', 'nginx', 'other']),
            state: z.string().max(40).optional(),
          })
          .strict(),
      )
      .max(200)
      .default([]),
    ports: z
      .array(
        z
          .object({
            port: z.number().int().min(1).max(65535),
            proto: z.enum(['tcp', 'udp']),
            processHint: z.string().max(120).optional(),
          })
          .strict(),
      )
      .max(500)
      .default([]),
  })
  .strict();

export const agentIdParamsSchema = z.object({ id: z.string().uuid() }).strict();
