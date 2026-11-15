import { z } from 'zod';

export const TEAM_ROLES = ['lead', 'developer', 'viewer'];

export const createTeamBodySchema = z
  .object({
    name: z.string().trim().min(2).max(120),
    slug: z
      .string()
      .trim()
      .min(2)
      .max(80)
      .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
  })
  .strict();

export const teamIdParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const teamMemberParamsSchema = z
  .object({ id: z.string().uuid(), userId: z.string().uuid() })
  .strict();

export const addMemberBodySchema = z
  .object({ userId: z.string().uuid(), teamRole: z.enum(TEAM_ROLES) })
  .strict();
