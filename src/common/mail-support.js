import { AppError } from './errors/app-error.js';
import { createScope } from './scope.js';

/** Phase 10 (TASK-034) shared helpers: stale-client tolerance and domain/server access for the mail modules. */
export const schemaRequired = () =>
  new AppError(501, 'SCHEMA_REQUIRED', 'Mail tables are not available until the Prisma client is regenerated (run prisma generate while the API is stopped)');

const STALE = /Unknown argument|Unknown field|is not a function|Cannot read properties of undefined|doesn't exist|does not exist|ServerMailService|DomainMailConfig|MailboxAccount|MailboxAuditEvent/i;

/** Returns the Prisma delegate or throws 501 SCHEMA_REQUIRED when the generated client predates the mail models. */
export function mailDelegate(prisma, name) {
  const d = prisma?.[name];
  if (!d) throw schemaRequired();
  return d;
}

/** Run a mail persistence call; a stale client or missing table degrades to 501 SCHEMA_REQUIRED. */
export async function guardSchema(fn) {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof AppError) throw e;
    if (STALE.test(String(e?.message))) throw schemaRequired();
    throw e;
  }
}

/**
 * Provisioning state. Phase 10C: provisioning is authorized per action by the approval gate (platform.gate, second person),
 * not by env allowlists. MAIL_PROVISIONING_DISABLED=true is an operator kill switch that blocks every remote mail action.
 */
export function provisioningState({ provisioningDisabled = false } = {}) {
  const killSwitch = provisioningDisabled === true;
  return { authorized: !killSwitch, killSwitch, requiresApproval: true };
}

export function createMailAccess({ prisma, rbac = null, now = () => new Date() }) {
  const scope = createScope({ prisma, now });

  async function loadDomain(id, actor) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    const row = await prisma.domain.findUnique({ where: { id }, include: { dnsRecords: true, server: { select: { id: true, alias: true, hostname: true } } } });
    if (!row || row.archivedAt) throw new AppError(404, 'DOMAIN_NOT_FOUND', 'Domain not found');
    if (actor.isOwner) return row;
    const visible = (await scope.canSeeProject(actor, row.projectId)) || (!row.projectId && (await scope.explicitServerIds(actor))?.includes(row.serverId));
    if (!visible) throw new AppError(404, 'DOMAIN_NOT_FOUND', 'Domain not found');
    return row;
  }

  /**
   * Writes: Owner, or the dedicated `mail.manage` permission (grant on the domain, or on its project, or a role),
   * or (backward compatible) project.configure on any environment of the domain project. Everyone else is denied.
   */
  async function requireWrite(actor, domain) {
    if (actor?.isOwner) return;
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (rbac?.can) {
      const scopes = [{ resourceType: 'domain', resourceId: domain.id }];
      if (domain.projectId) scopes.push({ resourceType: 'project', resourceId: domain.projectId });
      if (domain.serverId) scopes.push({ resourceType: 'server', resourceId: domain.serverId });
      for (const sc of scopes) if (await rbac.can(actor, { permissionKey: 'mail.manage', ...sc })) return;
    }
    if (domain.projectId && rbac?.can) {
      const envs = (await prisma.projectEnvironment?.findMany?.({ where: { projectId: domain.projectId } })) ?? [];
      for (const env of envs) {
        if (await rbac.can(actor, { permissionKey: 'project.configure', resourceType: 'project', resourceId: domain.projectId, environmentId: env.id })) return;
      }
    }
    throw new AppError(403, 'FORBIDDEN', 'You do not have permission to manage mail for this domain');
  }

  async function requireServerVisible(actor, serverId) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    await scope.requireServer(actor, serverId, 'SERVER_NOT_FOUND', 'Server not found');
    const row = await prisma.server.findUnique({ where: { id: serverId } });
    if (!row || row.archivedAt) throw new AppError(404, 'SERVER_NOT_FOUND', 'Server not found');
    return row;
  }

  return { loadDomain, requireWrite, requireServerVisible, scope };
}
