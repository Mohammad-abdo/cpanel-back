import { prisma } from '../../config/prisma.js';
import { createAuditService } from '../audit/audit.service.js';
import { createRbacService } from '../rbac/rbac.service.js';
import { createPlatformService } from './platform.service.js';
import { createSimulatedAdapters } from './platform.adapters.js';

let deps;

/** Shared singletons for route composition. Adapters default to the simulated (no real execution) set. */
export function getDeps() {
  if (!deps) {
    const auditService = createAuditService({ prisma });
    const rbac = createRbacService({ prisma, auditService });
    const platform = createPlatformService({ prisma, auditService, rbac });
    deps = { prisma, auditService, rbac, platform, adapters: createSimulatedAdapters() };
  }
  return deps;
}
