import { prisma } from '../../config/prisma.js';
import { createAuditService } from '../audit/audit.service.js';
import { createRbacService } from '../rbac/rbac.service.js';
import { createPlatformService } from './platform.service.js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSimulatedAdapters } from './platform.adapters.js';
import { resolveProviderAdapters } from '../root-domains/root-domains.adapters.js';
import { createSshConnector } from '../server-access/ssh.connector.js';

/** Simulated offsite backups persist under cpanel-back/.data/sim-offsite (override: NT_SIM_OFFSITE_DIR). */
const SIM_OFFSITE_DIR = process.env.NT_SIM_OFFSITE_DIR || path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..', '.data', 'sim-offsite');

let deps;

/** Shared singletons for route composition. Adapters default to the simulated (no real execution) set. */
export function getDeps() {
  if (!deps) {
    const auditService = createAuditService({ prisma });
    const rbac = createRbacService({ prisma, auditService });
    const platform = createPlatformService({ prisma, auditService, rbac });
    deps = { prisma, auditService, rbac, platform, adapters: { ...createSimulatedAdapters({ storeDir: SIM_OFFSITE_DIR }), ...resolveProviderAdapters({ prisma, createConnector: () => createSshConnector({ timeoutMs: 30_000 }) }) } };
  }
  return deps;
}
