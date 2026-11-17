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
  'alertChannels.retryDue': { env: 'NT_JOB_ALERT_CHANNEL_RETRY_MS', ms: 30_000 },
  'reports.runDue': { env: 'NT_JOB_REPORTS_MS', ms: 1 * MIN },
  'certificates.scanExpiry': { env: 'NT_JOB_CERT_SCAN_MS', ms: 6 * HOUR },
  'backups.planRetention': { env: 'NT_JOB_RETENTION_MS', ms: 24 * HOUR },
  'security.sync': { env: 'NT_JOB_SECURITY_SYNC_MS', ms: 15 * MIN },
  'accessReviews.startDue': { env: 'NT_JOB_ACCESS_REVIEW_MS', ms: 24 * HOUR },
  'deployments.sweepStuck': { env: 'NT_JOB_DEPLOY_SWEEP_MS', ms: 2 * MIN },
  'previews.cleanup': { env: 'NT_JOB_PREVIEW_CLEANUP_MS', ms: 10 * MIN },
  'certificates.probeLive': { env: 'NT_JOB_CERT_PROBE_MS', ms: 12 * HOUR },
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
    // Review cadence is an Owner policy decision (docs/DECISIONS.md); quarterly by default, 0 disables.
    accessReviewEveryDays: Number.isFinite(Number(env.NT_ACCESS_REVIEW_DAYS)) && env.NT_ACCESS_REVIEW_DAYS !== '' && env.NT_ACCESS_REVIEW_DAYS !== undefined ? Number(env.NT_ACCESS_REVIEW_DAYS) : 90,
  };
}

export function buildJobs(services, config) {
  const { operations, alerts, reports, certificates, backups, prisma, security, accessReviews, alertChannels } = services;
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
  // Security sync runs as the system actor unless a named Owner account is configured for attribution.
  if (security) {
    const actor = config.securitySyncActorId ? { id: config.securitySyncActorId, isOwner: true } : SYSTEM_ACTOR;
    jobs.push({ name: 'security.sync', intervalMs: every('security.sync'), run: () => security.sync({ sinceMinutes: 60 }, actor) });
  }
  if (alertChannels) {
    jobs.push({ name: 'alertChannels.retryDue', intervalMs: every('alertChannels.retryDue'), run: ({ at } = {}) => alertChannels.retryDue(at ?? new Date()) });
  }
  if (services.deploymentSweeper) {
    jobs.push({ name: 'deployments.sweepStuck', intervalMs: every('deployments.sweepStuck'), run: () => services.deploymentSweeper.sweepStuck() });
  }
  if (services.previews) {
    jobs.push({ name: 'previews.cleanup', intervalMs: every('previews.cleanup'), run: ({ at } = {}) => services.previews.cleanupExpired(at ?? new Date()) });
  }
  // Opt-in (CERT_EXPIRY_PROBE=1): opens TLS connections to registered domains.
  if (services.certProbeEnabled) {
    jobs.push({ name: 'certificates.probeLive', intervalMs: every('certificates.probeLive'), run: () => certificates.scanLive() });
  }
  if (accessReviews && config.accessReviewEveryDays > 0) {
    jobs.push({
      name: 'accessReviews.startDue',
      intervalMs: every('accessReviews.startDue'),
      run: ({ at } = {}) => accessReviews.startDue(at ?? new Date(), { everyDays: config.accessReviewEveryDays }),
    });
  }
  return jobs;
}
