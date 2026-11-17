import { prisma } from '../../config/prisma.js';
import { getDeps } from '../platform/platform.wiring.js';
import { resolveDeploymentAdapters } from '../deployments/deployments.ssh-runner.js';
import { createRootDomainsService } from '../root-domains/root-domains.service.js';
import { createPreviewsService } from './previews.service.js';

/** Preview service for background jobs (TTL cleanup). No deployment service is needed: cleanup only destroys. */
export function createPreviewsJobService() {
  const deps = getDeps();
  const runner = resolveDeploymentAdapters({ prisma }).runner;
  return createPreviewsService({ ...deps, prisma, rootDomains: createRootDomainsService({ ...deps, prisma }), teardown: (args) => runner.teardown(args) });
}

/** Opt-in (CERT_EXPIRY_PROBE=1): the live certificate scan opens TLS connections to registered domains. */
export const isCertProbeEnabled = (env = process.env) => ['1', 'true', 'on'].includes(String(env.CERT_EXPIRY_PROBE ?? '').toLowerCase());
