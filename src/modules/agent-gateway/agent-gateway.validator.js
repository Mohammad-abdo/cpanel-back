import { z } from 'zod';

/** No whitespace or shell metacharacters in identifiers the agent turns into argv. Agent re-validates independently. */
const safe = (max = 100) => z.string().min(1).max(max).regex(/^[A-Za-z0-9][A-Za-z0-9._\/@-]*$/);
const name = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/);
const absPath = z.string().min(1).max(512).regex(/^\/[^\0\\]*$/);

const strict = (shape) => z.object(shape).strict();

/** Per-command argument schemas (control-plane side). `password` is accepted for backup.dump and encrypted before sending. */
export const COMMAND_ARGS = {
  stats: strict({}),
  'file.list': strict({ path: absPath }),
  'file.read': strict({ path: absPath, maxBytes: z.number().int().min(1).max(262144).optional() }),
  'deploy.step': strict({
    step: z.enum(['git_fetch', 'git_checkout', 'npm_ci', 'npm_script', 'prisma_migrate_deploy']),
    dir: absPath,
    ref: safe(100).optional(),
    script: z.enum(['build', 'test', 'lint']).optional(),
  }),
  'pm2.control': strict({ action: z.enum(['list', 'restart', 'reload', 'stop', 'start', 'delete']), name: name.optional() }),
  ufw: strict({
    action: z.enum(['status', 'allow', 'deny', 'delete_allow']),
    port: z.number().int().min(1).max(65535).optional(),
    proto: z.enum(['tcp', 'udp']).optional(),
    from: z.string().regex(/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/).optional(),
  }),
  'cron.run': strict({ job: name }),
  'backup.dump': strict({
    kind: z.enum(['mysql', 'files']),
    database: name.optional(),
    user: name.optional(),
    password: z.string().min(1).max(256).optional(),
    sourceDir: absPath.optional(),
    outPath: absPath,
  }),
  'service.restart': strict({ unit: z.string().regex(/^[a-z0-9][a-z0-9@_.-]{0,62}$/) }),
};
export const COMMAND_TYPES = Object.keys(COMMAND_ARGS);

export const serverIdParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const sendCommandBodySchema = z
  .object({
    type: z.enum(COMMAND_TYPES),
    args: z.record(z.string(), z.unknown()).default({}),
    approvalId: z.string().uuid().optional(),
    reason: z.string().trim().min(3).max(500).optional(),
  })
  .strict();

export const historyQuerySchema = z
  .object({
    status: z.enum(['sent', 'succeeded', 'failed', 'expired']).optional(),
    limit: z.coerce.number().int().min(1).max(100).default(25),
  })
  .strict();

export const rotateBodySchema = z.object({ approvalId: z.string().uuid().optional(), reason: z.string().trim().min(3).max(500).optional() }).strict();
export const terminalBodySchema = z.object({ enabled: z.boolean(), approvalId: z.string().uuid().optional(), reason: z.string().trim().min(3).max(500).optional() }).strict();
