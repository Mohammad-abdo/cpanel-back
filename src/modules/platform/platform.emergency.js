import { timingSafeEqual } from 'node:crypto';
import { AppError } from '../../common/errors/app-error.js';
import { sha256, parseKey } from './platform.crypto.js';

const WINDOW_ACTIONS = ['platform.breakglass.activate', 'platform.breakglass.deactivate'];
const LOCK_WINDOW_MS = 15 * 60 * 1000;
export const MAX_FAILED_ATTEMPTS = 5;

/**
 * Emergency Owner access (break-glass). The Owner proves possession of an offline recovery code whose
 * SHA-256 is configured through the environment. Access is a short, audited window. This service records
 * and reports the window; enforcement inside rbac is NOT implemented (documented as a gap).
 */
export function createEmergencyService({ prisma, now = () => new Date(), auditService, recoveryCodeHash = () => process.env.EMERGENCY_RECOVERY_CODE_SHA256 }) {
  const audit = (event) => auditService.record({ resourceType: 'platform', resourceId: 'break-glass', ...event });

  async function latest() {
    const rows = await prisma.auditEvent.findMany({ where: { resourceType: 'platform', resourceId: 'break-glass', action: { in: WINDOW_ACTIONS }, result: 'success' }, orderBy: { occurredAt: 'desc' }, take: 1 });
    return rows[0] ?? null;
  }

  const view = (ev) => {
    const active = ev?.action === 'platform.breakglass.activate' && new Date(ev.afterJson?.expiresAt) > now();
    return { active, expiresAt: active ? ev.afterJson.expiresAt : null, activatedBy: active ? ev.actorId : null };
  };

  return {
    async status() {
      return view(await latest());
    },

    async activate({ reason, recoveryCode, minutes }, actor) {
      if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      if (!actor.isOwner) throw new AppError(403, 'OWNER_ONLY', 'Only the Owner can use emergency access');
      const expected = recoveryCodeHash();
      if (!expected || !/^[0-9a-f]{64}$/i.test(expected)) throw new AppError(503, 'BREAKGLASS_NOT_CONFIGURED', 'Emergency recovery code is not configured');
      const since = new Date(now().getTime() - LOCK_WINDOW_MS);
      const failures = await prisma.auditEvent.count({ where: { resourceType: 'platform', resourceId: 'break-glass', action: 'platform.breakglass.activate', result: 'denied', occurredAt: { gte: since } } });
      if (failures >= MAX_FAILED_ATTEMPTS) throw new AppError(429, 'BREAKGLASS_LOCKED', 'Too many failed attempts; try again later');
      const given = Buffer.from(sha256(recoveryCode), 'hex');
      const want = Buffer.from(expected.toLowerCase(), 'hex');
      if (given.length !== want.length || !timingSafeEqual(given, want)) {
        await audit({ actorId: actor.id, action: 'platform.breakglass.activate', result: 'denied', metadata: { reason: 'bad_recovery_code' } });
        throw new AppError(403, 'RECOVERY_CODE_INVALID', 'Recovery code is not valid');
      }
      if (view(await latest()).active) throw new AppError(409, 'BREAKGLASS_ACTIVE', 'Emergency access is already active');
      const expiresAt = new Date(now().getTime() + minutes * 60000).toISOString();
      await audit({ actorId: actor.id, action: 'platform.breakglass.activate', result: 'success', after: { expiresAt, reason } });
      return { active: true, expiresAt };
    },

    async deactivate({ note }, actor) {
      if (!actor?.isOwner) throw new AppError(403, 'OWNER_ONLY', 'Only the Owner can end emergency access');
      if (!view(await latest()).active) throw new AppError(409, 'BREAKGLASS_NOT_ACTIVE', 'Emergency access is not active');
      await audit({ actorId: actor.id, action: 'platform.breakglass.deactivate', result: 'success', after: { note: note ?? null } });
      return { active: false };
    },

    /** Platform recovery readiness. Unknowns stay unknown; nothing is reported as passed without evidence. */
    async readiness({ encryptionKey = () => process.env.BACKUP_ENCRYPTION_KEY } = {}) {
      const checks = [];
      const add = (name, status, detail) => checks.push({ name, status, detail });
      try {
        const owners = await prisma.user.count({ where: { ownerFlag: true, disabledAt: null } });
        add('owner_account_exists', owners >= 1 ? 'pass' : 'fail', `${owners} active Owner account(s)`);
      } catch {
        add('owner_account_exists', 'unknown', 'database not reachable');
      }
      try {
        parseKey(encryptionKey());
        add('backup_encryption_key_configured', 'pass', 'key present and valid length');
      } catch {
        add('backup_encryption_key_configured', 'fail', 'missing or invalid');
      }
      const h = recoveryCodeHash();
      add('emergency_recovery_code_configured', h && /^[0-9a-f]{64}$/i.test(h) ? 'pass' : 'fail', 'hash configured in environment');
      try {
        const last = await prisma.backupRun.findFirst({ where: { status: 'retained', verificationStatus: 'verified' }, orderBy: { finishedAt: 'desc' } });
        add('verified_backup_exists', last ? 'pass' : 'fail', last ? `latest verified ${new Date(last.finishedAt).toISOString()}` : 'no verified backup');
      } catch {
        add('verified_backup_exists', 'unknown', 'database not reachable');
      }
      add('offsite_control_plane_restore_drill', 'unknown', 'NOT_RUN: no recovery drill evidence exists');
      add('approved_rpo_rto', 'unknown', 'UNKNOWN: no approved RPO/RTO recorded');
      return { ready: checks.every((c) => c.status === 'pass'), checks };
    },
  };
}
