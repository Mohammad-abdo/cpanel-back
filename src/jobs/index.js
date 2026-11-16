import { prisma } from '../config/prisma.js';
import { createAuditService } from '../modules/audit/audit.service.js';
import { createOperationsService } from '../modules/operations/operations.service.js';
import { createDeploymentExecutor } from '../modules/deployments/deployments.executor.js';
import { createAlertsService } from '../modules/monitoring/monitoring.alerts.js';
import { createReportsService } from '../modules/reports/reports.service.js';
import { createCertificatesService } from '../modules/certificates/certificates.service.js';
import { createBackupsService } from '../modules/backups/backups.service.js';
import { createSecurityService } from '../modules/security/security.service.js';
import { createIncidentsService } from '../modules/incidents/incidents.service.js';
import { createAccessReviewsService } from '../modules/access-reviews/access-reviews.service.js';
import { getDeps } from '../modules/platform/platform.wiring.js';
import { logsService } from '../modules/logs/logs.routes.js';
import { serverAccessService } from '../modules/server-access/server-access.routes.js';
import { createScheduler } from './scheduler.js';
import { buildJobs, parseJobConfig } from './jobs.js';

export function createDefaultServices() {
  const deps = getDeps();
  const auditService = createAuditService({ prisma });
  const backups = createBackupsService({ ...deps, serverAccessService });
  return {
    prisma,
    operations: createOperationsService({
      prisma,
      auditService,
      executor: createDeploymentExecutor({ prisma, backups }),
    }),
    alerts: createAlertsService({ prisma, auditService, store: logsService.store }),
    reports: createReportsService({ prisma, auditService }),
    certificates: createCertificatesService(deps),
    backups,
    security: createSecurityService({ ...deps, incidents: createIncidentsService(deps) }),
    accessReviews: createAccessReviewsService(deps),
    auditService,
  };
}

/** Starts the in-process job scheduler unless NT_JOBS_ENABLED=false. Returns the scheduler or null. */
export function startJobs(env = process.env) {
  const config = parseJobConfig(env);
  if (!config.enabled) {
    console.info('[jobs] scheduler disabled (NT_JOBS_ENABLED=false)');
    return null;
  }
  const services = createDefaultServices();
  const scheduler = createScheduler({
    jobs: buildJobs(services, config),
    onFailure: ({ job, error }) =>
      services.auditService.record({
        actorId: null,
        action: 'job.failure',
        resourceType: 'job',
        resourceId: job,
        result: 'failure',
        metadata: { error },
      }),
  });
  scheduler.start();
  return scheduler;
}
