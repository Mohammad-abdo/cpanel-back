import { z } from 'zod';

const sha = z.string().regex(/^[0-9a-f]{7,40}$/);
const branch = z.string().regex(/^[A-Za-z0-9._/-]{1,100}$/);

export const listDeploymentsQuerySchema = z
  .object({
    projectId: z.string().uuid().optional(),
    limit: z.coerce.number().int().min(1).max(100).default(20),
  })
  .strict();

export const deploymentIdParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const createDeploymentBodySchema = z
  .object({
    projectId: z.string().uuid(),
    environmentId: z.string().uuid(),
    idempotencyKey: z.string().min(8).max(128),
    commitSha: sha.optional(),
    branch: branch.optional(),
    rollbackPlan: z.string().max(1000).optional(),
  })
  .strict();

export const rollbackBodySchema = z
  .object({
    idempotencyKey: z.string().min(8).max(128),
    targetDeploymentId: z.string().uuid().optional(),
    rollbackPlan: z.string().max(1000).optional(),
  })
  .strict();
