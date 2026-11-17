/**
 * Server-wide backup settings (vercel-clone parity). Runs fail closed unless BACKUP_EXECUTOR=ssh.
 */
import { AppError } from '../../common/errors/app-error.js';
import { resolveExecutorMode } from '../backups/backups.executor.js';

const STALE = /Unknown argument|Unknown field|is not a function|Cannot read properties of undefined|doesn't exist|does not exist|ServerBackupSettings/i;
const schemaRequired = () =>
  new AppError(
    501,
    'SCHEMA_REQUIRED',
    'Server backup settings are not available until the Prisma client is regenerated (run prisma generate while the API is stopped)',
  );

const DEFAULTS = {
  enabled: false,
  includeMysql: true,
  includePostgres: false,
  includeFiles: false,
  filesPath: null,
  retainCount: 7,
  scheduleCron: null,
  lastRunAt: null,
  lastStatus: null,
  lastError: null,
  metaJson: null,
};

export function createServerBackupsService({ prisma, auditService = null }) {
  const audit = (event) => (auditService?.record ? auditService.record({ resourceType: 'server_backup_settings', ...event }) : null);

  const table = () => {
    if (!prisma?.serverBackupSettings) throw schemaRequired();
    return prisma.serverBackupSettings;
  };

  async function guard(fn) {
    try {
      return await fn();
    } catch (e) {
      if (e instanceof AppError) throw e;
      if (STALE.test(String(e?.message))) throw schemaRequired();
      throw e;
    }
  }

  function requireOwner(actor) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (!actor.isOwner) throw new AppError(403, 'OWNER_ONLY', 'Only the Owner can manage server-wide backups');
  }

  async function requireServer(serverId) {
    const server = await prisma.server.findUnique({ where: { id: serverId } });
    if (!server || server.archivedAt) throw new AppError(404, 'SERVER_NOT_FOUND', 'Server not found');
    return server;
  }

  const view = (row, serverId) => ({
    serverId,
    id: row?.id ?? null,
    enabled: row?.enabled ?? DEFAULTS.enabled,
    includeMysql: row?.includeMysql ?? DEFAULTS.includeMysql,
    includePostgres: row?.includePostgres ?? DEFAULTS.includePostgres,
    includeFiles: row?.includeFiles ?? DEFAULTS.includeFiles,
    filesPath: row?.filesPath ?? DEFAULTS.filesPath,
    retainCount: row?.retainCount ?? DEFAULTS.retainCount,
    scheduleCron: row?.scheduleCron ?? DEFAULTS.scheduleCron,
    lastRunAt: row?.lastRunAt ?? DEFAULTS.lastRunAt,
    lastStatus: row?.lastStatus ?? DEFAULTS.lastStatus,
    lastError: row?.lastError ?? DEFAULTS.lastError,
    metaJson: row?.metaJson ?? DEFAULTS.metaJson,
    updatedAt: row?.updatedAt ?? null,
    createdAt: row?.createdAt ?? null,
  });

  return {
    async getSettings(serverId, actor) {
      if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      await requireServer(serverId);
      return guard(async () => {
        const row = await table().findUnique({ where: { serverId } });
        return view(row, serverId);
      });
    },

    async putSettings(serverId, input, actor) {
      requireOwner(actor);
      await requireServer(serverId);
      return guard(async () => {
        if (input.includeFiles && input.filesPath && input.filesPath.includes('\0')) {
          throw new AppError(422, 'FILES_PATH_INVALID', 'filesPath must not contain NUL bytes');
        }
        const data = {
          enabled: input.enabled,
          includeMysql: input.includeMysql,
          includePostgres: input.includePostgres,
          includeFiles: input.includeFiles,
          filesPath: input.includeFiles ? (input.filesPath?.trim() || null) : null,
          retainCount: input.retainCount,
          scheduleCron: input.scheduleCron?.trim() || null,
        };
        const row = await table().upsert({
          where: { serverId },
          create: { serverId, ...data },
          update: data,
        });
        await audit({
          actorId: actor.id,
          action: 'server.backup.settings',
          resourceId: row.id,
          result: 'success',
          after: { serverId, enabled: row.enabled, retainCount: row.retainCount },
        });
        return view(row, serverId);
      });
    },

    async runNow(serverId, actor) {
      requireOwner(actor);
      await requireServer(serverId);
      return guard(async () => {
        let row = await table().findUnique({ where: { serverId } });
        if (!row) {
          row = await table().create({ data: { serverId, ...DEFAULTS } });
        }
        if (!row.enabled) {
          throw new AppError(409, 'SERVER_BACKUP_DISABLED', 'Enable server-wide backups before running');
        }
        const mode = resolveExecutorMode();
        const at = new Date();
        const notice =
          mode === 'ssh'
            ? 'Run queued for the SSH backup executor'
            : 'BACKUP_EXECUTOR is simulated by default; set BACKUP_EXECUTOR=ssh on the API for real server dumps';
        row = await table().update({
          where: { serverId },
          data: { lastRunAt: at, lastStatus: 'queued', lastError: null },
        });
        await audit({
          actorId: actor.id,
          action: 'server.backup.run',
          resourceId: row.id,
          result: 'success',
          after: {
            serverId,
            lastRunAt: at.toISOString(),
            executorMode: mode,
            notice,
            includeMysql: row.includeMysql,
            includePostgres: row.includePostgres,
            includeFiles: row.includeFiles,
          },
        });
        if (mode !== 'ssh') {
          await table().update({
            where: { serverId },
            data: {
              lastStatus: 'failed',
              lastError: 'BACKUP_EXECUTOR_DISABLED (simulated)',
            },
          });
          throw new AppError(
            409,
            'BACKUP_EXECUTOR_DISABLED',
            'Server-wide backup execution requires BACKUP_EXECUTOR=ssh on the API process',
          );
        }
        return {
          serverId,
          status: 'queued',
          lastRunAt: at.toISOString(),
          executorMode: mode,
          notice: 'Server-wide backup run recorded; executor integration uses BACKUP_EXECUTOR=ssh',
          settings: view(row, serverId),
        };
      });
    },
  };
}