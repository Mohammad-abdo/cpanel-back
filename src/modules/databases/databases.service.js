import { createHash, randomBytes } from 'node:crypto';
import { AppError } from '../../common/errors/app-error.js';
import { createScope } from '../../common/scope.js';
import { assertCan } from '../platform/platform.service.js';
import { PERM } from '../platform/platform.risk.js';
import { decrypt, encrypt } from '../platform/platform.crypto.js';

const RESERVED = new Set(['mysql', 'sys', 'information_schema', 'performance_schema', 'root', 'admin']);
const SAFETY_BACKUP_MAX_AGE_MS = 24 * 3600 * 1000;
export const GRANTS = { read: ['SELECT'], readwrite: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] };

function presentInstance(row) {
  if (!row) return row;
  const { adminSecretEnc, ...rest } = row;
  return {
    ...rest,
    hasAdminLogin: Boolean(adminSecretEnc && rest.adminUsername),
    adminSecretEnc: undefined,
  };
}

export function createDatabasesService({
  prisma,
  now = () => new Date(),
  auditService = null,
  rbac = null,
  platform = null,
  adapters = null,
  serverAccessService = null,
  credentialKey = () => process.env.CREDENTIAL_ENCRYPTION_KEY,
}) {
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);

  async function authorize(actor, projectId, environmentId) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    const env = await prisma.projectEnvironment.findUnique({ where: { id: environmentId } });
    if (!env || env.projectId !== projectId) throw new AppError(409, 'ENVIRONMENT_PROJECT_MISMATCH', 'Environment does not belong to this project');
    await assertCan(rbac, actor, { permissionKey: PERM.DATABASE, resourceType: 'project', resourceId: projectId, environmentId });
  }

  const scope = createScope({ prisma, now });

  function requireOwner(actor) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (!actor.isOwner) throw new AppError(403, 'OWNER_ONLY', 'Only the Owner can manage database logins');
  }

  async function loadDb(id) {
    const db = await prisma.managedDatabase.findUnique({ where: { id }, include: { instance: true, users: true } });
    if (!db) throw new AppError(404, 'DATABASE_NOT_FOUND', 'Database not found');
    return db;
  }

  async function loadInstance(id, actor) {
    const row = await prisma.databaseInstance.findUnique({ where: { id } });
    if (!row) throw new AppError(404, 'INSTANCE_NOT_FOUND', 'Database instance not found');
    if (row.serverId) await scope.requireServer(actor, row.serverId, 'SERVER_NOT_FOUND', 'Server not found');
    return row;
  }

  function instanceAuth(row) {
    if (!row.adminUsername || !row.adminSecretEnc) return null;
    return {
      username: row.adminUsername,
      password: decrypt(Buffer.from(row.adminSecretEnc), credentialKey()).toString('utf8'),
    };
  }

  /**
   * Prefer live MySQL over SSH when the instance is linked to a server and has a saved login.
   * Owner MFA is required for the SSH path (same gate as dump/restore). Otherwise simulated adapter.
   */
  async function runDbAdmin(instance, op, args, actor) {
    const auth = instanceAuth(instance);
    if (instance.serverId && auth) {
      if (!actor?.isOwner) {
        throw new AppError(
          403,
          'LIVE_DB_OWNER_REQUIRED',
          'Provisioning a real MySQL database on the server requires the Owner (SSH admin path)',
        );
      }
      if (!serverAccessService?.dbManage) {
        throw new AppError(501, 'DB_MANAGE_UNAVAILABLE', 'Live database management is not available');
      }
      return serverAccessService.dbManage(
        instance.serverId,
        { engine: instance.engine, auth, op, ...args },
        actor,
      );
    }
    if (!adapters?.dbAdmin) throw new AppError(501, 'DB_ADMIN_UNAVAILABLE', 'Database admin adapter is not configured');
    if (op === 'createDatabase') await adapters.dbAdmin.createDatabase({ instance: instance.name, dbName: args.dbName });
    else if (op === 'createUser') {
      await adapters.dbAdmin.createUser({
        instance: instance.name,
        username: args.username,
        password: args.password,
        host: args.host || '127.0.0.1',
        scope: `${args.dbName}.*`,
        grants: args.grants,
        grantOption: false,
      });
    } else if (op === 'dropDatabase') await adapters.dbAdmin.dropDatabase({ instance: instance.name, dbName: args.dbName });
    else throw new AppError(422, 'DB_OP_INVALID', 'Unknown database management operation');
    return { ok: true, simulated: true, op };
  }

  return {
    async listInstances(actor) {
      const serverId = await scope.serverClause(actor);
      const rows = await prisma.databaseInstance.findMany({ where: serverId ? { serverId } : {}, orderBy: { name: 'asc' } });
      return rows.map(presentInstance);
    },

    async getInstance(id, actor) {
      return presentInstance(await loadInstance(id, actor));
    },

    /** Owner MFA: store encrypted admin password for live SSH browse. Password is never returned. */
    async setInstanceLogin(id, { username, password }, actor) {
      requireOwner(actor);
      const row = await loadInstance(id, actor);
      if (row.engine !== 'mysql' && row.engine !== 'postgres') {
        throw new AppError(422, 'ENGINE_UNSUPPORTED', 'Login is only supported for MySQL and Postgres');
      }
      const secretEnc = encrypt(password, credentialKey());
      const updated = await prisma.databaseInstance.update({
        where: { id },
        data: { adminUsername: username, adminSecretEnc: secretEnc },
      });
      await audit({
        actorId: actor.id,
        action: 'db.instance.login.set',
        resourceType: 'database_instance',
        resourceId: id,
        result: 'success',
        after: { username, engine: row.engine },
      });
      return presentInstance(updated);
    },

    async clearInstanceLogin(id, actor) {
      requireOwner(actor);
      await loadInstance(id, actor);
      const updated = await prisma.databaseInstance.update({
        where: { id },
        data: { adminUsername: null, adminSecretEnc: null },
      });
      await audit({
        actorId: actor.id,
        action: 'db.instance.login.clear',
        resourceType: 'database_instance',
        resourceId: id,
        result: 'success',
      });
      return presentInstance(updated);
    },

    /** Live browse via SSH using saved instance login when present. */
    async liveBrowse(id, params, actor) {
      requireOwner(actor);
      if (!serverAccessService?.dbBrowse) throw new AppError(500, 'LIVE_UNAVAILABLE', 'Live database browse is not wired');
      const row = await loadInstance(id, actor);
      if (!row.serverId) throw new AppError(409, 'INSTANCE_NO_SERVER', 'This instance is not linked to a server');
      if (row.engine !== 'mysql' && row.engine !== 'postgres') {
        throw new AppError(422, 'ENGINE_UNSUPPORTED', 'Live browse supports MySQL and Postgres only');
      }
      const auth = instanceAuth(row);
      return serverAccessService.dbBrowse(
        row.serverId,
        { engine: row.engine, auth, ...params },
        actor,
      );
    },

    async liveDump(id, { db = null } = {}, actor) {
      requireOwner(actor);
      if (!serverAccessService?.dbDump) throw new AppError(500, 'LIVE_UNAVAILABLE', 'Live dump is not wired');
      const row = await loadInstance(id, actor);
      if (!row.serverId) throw new AppError(409, 'INSTANCE_NO_SERVER', 'This instance is not linked to a server');
      if (row.engine !== 'mysql' && row.engine !== 'postgres') {
        throw new AppError(422, 'ENGINE_UNSUPPORTED', 'Dump supports MySQL and Postgres only');
      }
      return serverAccessService.dbDump(row.serverId, { engine: row.engine, db: db || null, auth: instanceAuth(row) }, actor);
    },

    async liveRestore(id, { db = null, bytes, confirm, reason, rollbackNote, approvalId }, actor) {
      requireOwner(actor);
      if (!serverAccessService?.dbRestore) throw new AppError(500, 'LIVE_UNAVAILABLE', 'Live restore is not wired');
      const row = await loadInstance(id, actor);
      if (!row.serverId) throw new AppError(409, 'INSTANCE_NO_SERVER', 'This instance is not linked to a server');
      if (row.engine !== 'mysql' && row.engine !== 'postgres') {
        throw new AppError(422, 'ENGINE_UNSUPPORTED', 'Restore supports MySQL and Postgres only');
      }
      // Typed confirmation and a sane upload are checked before an approval is ever requested.
      const target = db || 'ALL';
      if (confirm !== target) throw new AppError(422, 'CONFIRM_MISMATCH', `Type ${target} to confirm restore`);
      if (!Buffer.isBuffer(bytes) || bytes.length < 8) throw new AppError(422, 'DUMP_INVALID', 'Upload a non-empty .sql dump');
      if (!platform?.gate) throw new AppError(500, 'GATE_UNAVAILABLE', 'Approval service is not wired');
      const gate = await platform.gate(
        {
          action: 'db.restore.live',
          // Bound to the target and the exact dump content: an approval cannot be reused for another file.
          binding: `${target}:${createHash('sha256').update(bytes).digest('hex')}`,
          resourceType: 'database_instance',
          resourceId: id,
          approvalId,
          reason,
          impact: [`Restore a ${bytes.length}-byte SQL dump into ${target} on ${row.engine} instance ${row.name}`, 'Existing data may be overwritten'],
          rollbackPlan: rollbackNote,
          context: { engine: row.engine, target, bytes: bytes.length },
        },
        actor,
      );
      if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      return serverAccessService.dbRestore(
        row.serverId,
        { engine: row.engine, db: db || null, auth: instanceAuth(row), bytes, confirm },
        actor,
      );
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
      const out = presentInstance(row);
      return schemaPending ? { ...out, schemaPending: true } : out;
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
      const provision = await runDbAdmin(instance, 'createDatabase', { dbName: input.dbName }, actor);
      const row = await prisma.managedDatabase.create({ data: { projectId: input.projectId, environmentId: input.environmentId, instanceId: input.instanceId, dbName: input.dbName } });
      await audit({
        actorId: actor.id,
        action: 'db.create',
        resourceType: 'database',
        resourceId: row.id,
        environmentId: input.environmentId,
        result: 'success',
        after: { dbName: input.dbName, simulated: Boolean(provision.simulated) },
      });
      return { ...row, simulated: Boolean(provision.simulated) };
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
      const provision = await runDbAdmin(
        db.instance,
        'createUser',
        { dbName: db.dbName, username: input.username, password, host: '127.0.0.1', grants: privileges.grants },
        actor,
      );
      const row = await prisma.databaseUser.create({ data: { managedDatabaseId: id, username: input.username, privilegesJson: privileges } });
      await audit({
        actorId: actor.id,
        action: 'db.user.create',
        resourceType: 'database',
        resourceId: id,
        environmentId: db.environmentId,
        result: 'success',
        after: { username: input.username, privileges, simulated: Boolean(provision.simulated) },
      });
      // The password is returned exactly once and is never stored or audited.
      return {
        user: { id: row.id, username: row.username, privilegesJson: privileges },
        password,
        shownOnce: true,
        simulated: Boolean(provision.simulated),
      };
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
      const provision = await runDbAdmin(db.instance, 'dropDatabase', { dbName: db.dbName }, actor);
      await prisma.managedDatabase.delete({ where: { id } });
      await audit({
        actorId: actor.id,
        action: 'db.drop',
        resourceType: 'database',
        resourceId: id,
        environmentId: db.environmentId,
        result: 'success',
        before: { dbName: db.dbName, safetyBackupRunId: run.id, simulated: Boolean(provision.simulated) },
      });
      return { dropped: true, simulated: Boolean(provision.simulated) };
    },
  };
}
