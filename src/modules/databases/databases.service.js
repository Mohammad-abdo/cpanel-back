import { randomBytes } from 'node:crypto';
import { AppError } from '../../common/errors/app-error.js';
import { createScope } from '../../common/scope.js';
import { assertCan } from '../platform/platform.service.js';
import { PERM } from '../platform/platform.risk.js';

const RESERVED = new Set(['mysql', 'sys', 'information_schema', 'performance_schema', 'root', 'admin']);
const SAFETY_BACKUP_MAX_AGE_MS = 24 * 3600 * 1000;
export const GRANTS = { read: ['SELECT'], readwrite: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] };

export function createDatabasesService({ prisma, now = () => new Date(), auditService = null, rbac = null, platform = null, adapters = null }) {
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);

  async function authorize(actor, projectId, environmentId) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    const env = await prisma.projectEnvironment.findUnique({ where: { id: environmentId } });
    if (!env || env.projectId !== projectId) throw new AppError(409, 'ENVIRONMENT_PROJECT_MISMATCH', 'Environment does not belong to this project');
    await assertCan(rbac, actor, { permissionKey: PERM.DATABASE, resourceType: 'project', resourceId: projectId, environmentId });
  }

  const scope = createScope({ prisma, now });

  async function loadDb(id) {
    const db = await prisma.managedDatabase.findUnique({ where: { id }, include: { instance: true, users: true } });
    if (!db) throw new AppError(404, 'DATABASE_NOT_FOUND', 'Database not found');
    return db;
  }

  return {
    async listInstances(actor) {
      const serverId = await scope.serverClause(actor);
      return prisma.databaseInstance.findMany({ where: serverId ? { serverId } : {}, orderBy: { name: 'asc' } });
    },

    async createInstance(input, actor) {
      if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      const resourceType = input.serverId ? 'server' : 'platform';
      const resourceId = input.serverId ?? 'platform';
      await assertCan(rbac, actor, { permissionKey: PERM.DATABASE, resourceType, resourceId, environmentId: null });
      if (input.serverId) await scope.requireServer(actor, input.serverId, 'SERVER_NOT_FOUND', 'Server not found');
      const dup = await prisma.databaseInstance.findFirst({ where: { engine: input.engine, name: input.name } });
      if (dup) throw new AppError(409, 'INSTANCE_EXISTS', 'Database instance already exists');
      const gate = await platform.gate(
        { action: 'db.instance.register', binding: `${input.engine}:${input.name}`, resourceType, resourceId, approvalId: input.approvalId, reason: input.reason, impact: [`Register ${input.engine} instance ${input.name}`], rollbackPlan: input.rollbackNote, context: { engine: input.engine } },
        actor,
      );
      if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      const base = { engine: input.engine, name: input.name, serverId: input.serverId ?? null, status: 'registered' };
      const extra = { host: input.host ?? null, port: input.port ?? null, adminSecretRef: input.adminSecretRef ?? null };
      let row;
      let schemaPending = false;
      try {
        row = await prisma.databaseInstance.create({ data: { ...base, ...extra } });
      } catch (err) {
        // Stale generated client: retry with the legacy fields only and flag it.
        if (!/Unknown argument/i.test(String(err?.message))) throw err;
        row = await prisma.databaseInstance.create({ data: base });
        schemaPending = true;
      }
      await audit({ actorId: actor.id, action: 'db.instance.register', resourceType: 'database_instance', resourceId: row.id, result: 'success', after: { engine: input.engine, name: input.name, serverId: input.serverId ?? null, host: input.host ?? null, port: input.port ?? null, adminSecretRef: input.adminSecretRef ?? null } });
      return schemaPending ? { ...row, schemaPending: true } : row;
    },

    async list({ projectId, limit }, actor) {
      const projectClause = await scope.projectClause(actor, projectId);
      const rows = await prisma.managedDatabase.findMany({ where: projectClause ? { projectId: projectClause } : {}, take: limit, orderBy: { dbName: 'asc' }, include: { users: true, instance: true } });
      // Users expose scope only; credentials are never persisted.
      return rows.map((r) => ({ ...r, users: r.users.map((u) => ({ id: u.id, username: u.username, privilegesJson: u.privilegesJson })) }));
    },

    async create(input, actor) {
      await authorize(actor, input.projectId, input.environmentId);
      if (RESERVED.has(input.dbName)) throw new AppError(422, 'DB_NAME_RESERVED', 'Database name is reserved');
      const instance = await prisma.databaseInstance.findUnique({ where: { id: input.instanceId } });
      if (!instance) throw new AppError(404, 'INSTANCE_NOT_FOUND', 'Database instance not found');
      if (instance.engine !== 'mysql') throw new AppError(422, 'ENGINE_UNSUPPORTED', 'Only MySQL instances are managed');
      const dup = await prisma.managedDatabase.findFirst({ where: { projectId: input.projectId, environmentId: input.environmentId, dbName: input.dbName } });
      if (dup) throw new AppError(409, 'DATABASE_EXISTS', 'Database already exists for this environment');
      const gate = await platform.gate(
        { action: 'db.create', binding: input.dbName, resourceType: 'project', resourceId: input.projectId, approvalId: input.approvalId, reason: input.reason, impact: [`Create database ${input.dbName} on instance ${instance.name}`], rollbackPlan: input.rollbackNote, context: { environmentId: input.environmentId, dbName: input.dbName } },
        actor,
      );
      if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      await adapters.dbAdmin.createDatabase({ instance: instance.name, dbName: input.dbName });
      const row = await prisma.managedDatabase.create({ data: { projectId: input.projectId, environmentId: input.environmentId, instanceId: input.instanceId, dbName: input.dbName } });
      await audit({ actorId: actor.id, action: 'db.create', resourceType: 'database', resourceId: row.id, environmentId: input.environmentId, result: 'success', after: { dbName: input.dbName } });
      return row;
    },

    /** Scoped access: grants only on this database, only the requested level, never GRANT OPTION or global. */
    async createUser(id, input, actor) {
      const db = await loadDb(id);
      if (input.environmentId !== db.environmentId) {
        throw new AppError(409, 'ENVIRONMENT_MISMATCH', 'Database belongs to a different environment');
      }
      await authorize(actor, db.projectId, db.environmentId);
      if (RESERVED.has(input.username)) throw new AppError(422, 'DB_USER_RESERVED', 'Username is reserved');
      if (db.users.some((u) => u.username === input.username)) throw new AppError(409, 'DB_USER_EXISTS', 'User already exists');
      const privileges = { scope: `${db.dbName}.*`, grants: GRANTS[input.level], level: input.level, grantOption: false };
      const gate = await platform.gate(
        { action: 'db.user.create', binding: `${input.username}:${input.level}`, resourceType: 'database', resourceId: id, approvalId: input.approvalId, reason: input.reason, impact: [`Create user ${input.username} with ${input.level} on ${privileges.scope}`], rollbackPlan: input.rollbackNote, context: { environmentId: db.environmentId } },
        actor,
      );
      if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      const password = randomBytes(18).toString('base64url');
      await adapters.dbAdmin.createUser({ instance: db.instance.name, username: input.username, password, host: '127.0.0.1', ...privileges });
      const row = await prisma.databaseUser.create({ data: { managedDatabaseId: id, username: input.username, privilegesJson: privileges } });
      await audit({ actorId: actor.id, action: 'db.user.create', resourceType: 'database', resourceId: id, environmentId: db.environmentId, result: 'success', after: { username: input.username, privileges } });
      // The password is returned exactly once and is never stored or audited.
      return { user: { id: row.id, username: row.username, privilegesJson: privileges }, password, shownOnce: true };
    },

    async drop(id, input, actor) {
      const db = await loadDb(id);
      if (input.environmentId !== db.environmentId) throw new AppError(409, 'ENVIRONMENT_MISMATCH', 'Database belongs to a different environment');
      await authorize(actor, db.projectId, db.environmentId);
      if (input.confirmName !== db.dbName) throw new AppError(422, 'CONFIRM_NAME_MISMATCH', 'Confirmation name does not match');
      const run = await prisma.backupRun.findUnique({ where: { id: input.safetyBackupRunId }, include: { policy: true } });
      const fresh = run?.finishedAt && now().getTime() - new Date(run.finishedAt).getTime() <= SAFETY_BACKUP_MAX_AGE_MS;
      if (!run || run.policy.projectId !== db.projectId || run.status !== 'retained' || run.verificationStatus !== 'verified' || !fresh) {
        throw new AppError(409, 'SAFETY_BACKUP_REQUIRED', 'A verified backup of this project from the last 24 hours is required');
      }
      const gate = await platform.gate(
        { action: 'db.drop', resourceType: 'database', resourceId: id, approvalId: input.approvalId, reason: input.reason, impact: [`Permanently drop ${db.dbName} and ${db.users.length} user(s)`, `Safety backup run ${run.id}`], rollbackPlan: input.rollbackNote, context: { environmentId: db.environmentId } },
        actor,
      );
      if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      await adapters.dbAdmin.dropDatabase({ instance: db.instance.name, dbName: db.dbName });
      await prisma.managedDatabase.delete({ where: { id } });
      await audit({ actorId: actor.id, action: 'db.drop', resourceType: 'database', resourceId: id, environmentId: db.environmentId, result: 'success', before: { dbName: db.dbName, safetyBackupRunId: run.id } });
      return { dropped: true, simulated: Boolean(adapters.simulated) };
    },
  };
}
