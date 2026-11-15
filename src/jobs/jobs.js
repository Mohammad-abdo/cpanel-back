/**
 * Background job definitions. Each job calls an existing service method; no job executes
 * anything on a real server (adapters stay simulated) and retention is a dry-run plan only.
 */
import { SYSTEM_ACTOR } from '../common/system-actor.js';

const MIN = 60_000;
const HOUR = 60 * MIN;

const DEFAULTS = {
  'backups.runDue': { env: 'NT_JOB_BACKUP_RUN_MS', ms: 5 * MIN },
  'backups.verifyLatest': { env: 'NT_JOB_BACKUP_VERIFY_MS', ms: 24 * HOUR },
  'operations.expireStale': { env: 'NT_JOB_OPS_EXPIRE_MS', ms: 5 * MIN },
  'alerts.evaluateAll': { env: 'NT_JOB_ALERT_EVAL_MS', ms: 1 * MIN },
  'alerts.escalateDue': { env: 'NT_JOB_ALERT_ESCALATE_MS', ms: 5 * MIN },
  'reports.runDue': { env: 'NT_JOB_REPORTS_MS', ms: 1 * MIN },
  'certificates.scanExpiry': { env: 'NT_JOB_CERT_SCAN_MS', ms: 6 * HOUR },
  'backups.planRetention': { env: 'NT_JOB_RETENTION_MS', ms: 24 * HOUR },
  'security.sync': { env: 'NT_JOB_SECURITY_SYNC_MS', ms: 15 * MIN },
};

/** Minimum accepted interval: values below it (or non-numeric) fall back to the default. */
const MIN_INTERVAL_MS = 1000;

export { SYSTEM_ACTOR };

export function parseJobConfig(env = process.env) {
  const intervals = {};
  for (const [name, { env: key, ms }] of Object.entries(DEFAULTS)) {
    const n = Number(env[key]);
    intervals[name] = Number.isFinite(n) && n >= MIN_INTERVAL_MS ? n : ms;
  }
  return {
    enabled: String(env.NT_JOBS_ENABLED ?? 'true').toLowerCase() !== 'false',
    intervals,
    securitySyncActorId: env.NT_SECURITY_SYNC_ACTOR_ID || null,
  };
}

export function buildJobs(services, config) {
  const { operations, alerts, reports, certificates, backups, prisma, security } = services;
  const every = (name) => config.intervals[name];
  const jobs = [
    { name: 'operations.expireStale', intervalMs: every('operations.expireStale'), run: () => operations.expireStale() },
    { name: 'alerts.evaluateAll', intervalMs: every('alerts.evaluateAll'), run: ({ at } = {}) => alerts.evaluateAll(at ?? new Date()) },
    { name: 'alerts.escalateDue', intervalMs: every('alerts.escalateDue'), run: ({ at } = {}) => alerts.escalateDue(at ?? new Date()) },
    { name: 'reports.runDue', intervalMs: every('reports.runDue'), run: ({ at } = {}) => reports.runDue(at ?? new Date()) },
    { name: 'certificates.scanExpiry', intervalMs: every('certificates.scanExpiry'), run: () => certificates.scanExpiry() },
    { name: 'backups.runDue', intervalMs: every('backups.runDue'), run: ({ at } = {}) => backups.runDue(at ?? new Date()) },
    { name: 'backups.verifyLatest', intervalMs: every('backups.verifyLatest'), run: ({ at } = {}) => backups.verifyLatest(at ?? new Date()) },
    {
      name: 'backups.planRetention',
      intervalMs: every('backups.planRetention'),
      run: async () => {
        const policies = await prisma.backupPolicy.findMany({ where: { archivedAt: null } });
        const plans = [];
        for (const p of policies) plans.push(await backups.planRetention(p.id, SYSTEM_ACTOR));
        return plans;
      },
    },
  ];
  // Security sync acts on behalf of a named Owner account, so it only runs when one is configured.
  if (config.securitySyncActorId && security) {
    jobs.push({
      name: 'security.sync',
      intervalMs: every('security.sync'),
      run: () => security.sync({ sinceMinutes: 60 }, { id: config.securitySyncActorId, isOwner: true }),
    });
  }
  return jobs;
}
