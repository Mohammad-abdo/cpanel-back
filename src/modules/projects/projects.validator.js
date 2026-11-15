import { z } from 'zod';

const PROJECT_TYPES = ['node', 'laravel', 'wordpress', 'static', 'custom'];
const PROCESS_MANAGERS = ['pm2', 'systemd', 'php-fpm', 'apache', 'nginx', 'none', 'custom'];
const slug = z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/);
const envCode = z.string().regex(/^[a-z][a-z0-9-]{0,31}$/);
const remoteUrl = z.string().min(5).max(300);
const branch = z.string().regex(/^[A-Za-z0-9._/-]{1,100}$/);
const sha = z.string().regex(/^[0-9a-f]{7,40}$/);

export const listProjectsQuerySchema = z
  .object({
    limit: z.coerce.number().int().min(1).max(100).default(20),
    cursor: z.string().uuid().optional(),
    serverId: z.string().uuid().optional(),
  })
  .strict();

export const projectIdParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const lifecycleParamsSchema = z
  .object({ id: z.string().uuid(), action: z.enum(['start', 'stop', 'restart']) })
  .strict();

const environmentsSchema = z
  .array(z.object({ code: envCode, displayName: z.string().min(1).max(80) }).strict())
  .min(1)
  .max(10);

const repositorySchema = z.object({ remoteUrl: remoteUrl.optional(), defaultBranch: branch.optional() }).strict();
const runtimeSchema = z
  .object({ runtime: z.string().max(60).optional(), processManager: z.enum(PROCESS_MANAGERS).optional() })
  .strict();

export const createProjectBodySchema = z
  .object({
    serverId: z.string().uuid(),
    name: z.string().min(1).max(120),
    slug,
    type: z.enum(PROJECT_TYPES),
    environments: environmentsSchema,
    repository: repositorySchema.optional(),
    runtime: runtimeSchema.optional(),
  })
  .strict();

export const discoverBodySchema = z
  .object({
    serverId: z.string().uuid(),
    candidates: z
      .array(
        z
          .object({
            name: z.string().min(1).max(120),
            slug: slug.optional(),
            type: z.enum(PROJECT_TYPES).default('custom'),
            runtime: z.string().max(60).optional(),
            processManager: z.enum(PROCESS_MANAGERS).optional(),
            remoteUrl: remoteUrl.optional(),
            branch: branch.optional(),
            commitSha: sha.optional(),
            path: z.string().max(300).optional(),
          })
          .strict(),
      )
      .min(1)
      .max(100),
  })
  .strict();

export const linkBodySchema = z.object({ environments: environmentsSchema }).strict();

/** Secret values are never accepted: only reference names. `.strict()` rejects any other key. */
export const configureBodySchema = z
  .object({
    type: z.enum(PROJECT_TYPES).optional(),
    repository: repositorySchema.optional(),
    runtime: runtimeSchema.optional(),
    secretRefs: z.array(z.string().regex(/^[A-Z][A-Z0-9_]{0,63}$/)).max(100).optional(),
  })
  .strict();

export const lifecycleBodySchema = z
  .object({
    environmentId: z.string().uuid(),
    idempotencyKey: z.string().min(8).max(128),
    reason: z.string().max(300).optional(),
  })
  .strict();

export const archiveBodySchema = z.object({ reason: z.string().min(3).max(300) }).strict();

export const projectOverviewQuerySchema = z.object({ environmentId: z.string().uuid().optional() }).strict();

export const projectRoleSchema = z.enum(['lead', 'developer', 'viewer']);
export const projectTeamBodySchema = z.object({ teamId: z.string().uuid() }).strict();
export const projectMemberBodySchema = z.object({ userId: z.string().uuid(), projectRole: projectRoleSchema }).strict();
export const projectMemberRoleBodySchema = z.object({ projectRole: projectRoleSchema }).strict();
export const projectTeamParamsSchema = z.object({ id: z.string().uuid(), teamId: z.string().uuid() }).strict();
export const projectMemberParamsSchema = z.object({ id: z.string().uuid(), userId: z.string().uuid() }).strict();
