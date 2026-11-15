import { z } from 'zod';

export const STATES = ['detected', 'triaged', 'assigned', 'investigating', 'contained', 'resolved', 'closed'];

export const incidentIdParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const listIncidentsQuerySchema = z
  .object({ status: z.enum(STATES).optional(), limit: z.coerce.number().int().min(1).max(100).default(25) })
  .strict();

export const createIncidentBodySchema = z
  .object({ title: z.string().min(5).max(200), severity: z.enum(['critical', 'high', 'medium', 'low']) })
  .strict();

export const transitionBodySchema = z
  .object({ to: z.enum(STATES), note: z.string().min(3).max(1000).optional() })
  .strict();

export const assignBodySchema = z.object({ userId: z.string().uuid() }).strict();

export const evidenceBodySchema = z
  .object({ type: z.enum(['log', 'screenshot_ref', 'note', 'command_output', 'event_ref']), summary: z.string().min(3).max(2000) })
  .strict();

export const escalateBodySchema = z
  .object({ severity: z.enum(['critical', 'high', 'medium']), reason: z.string().min(5).max(500) })
  .strict();

export const reopenBodySchema = z.object({ reason: z.string().min(5).max(500) }).strict();
