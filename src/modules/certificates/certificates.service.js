import { AppError } from '../../common/errors/app-error.js';
import { createScope } from '../../common/scope.js';
import { assertCan } from '../platform/platform.service.js';
import { PERM } from '../platform/platform.risk.js';
import { notifyChannels } from '../notifications/notifications.service.js';
import { probeTls } from './certificates.probe.js';

export const RENEW_WINDOW_DAYS = 30;
const DAY = 86400000;

/** Derived state: an expired certificate is reported as expired even if the stored status is stale. */
export function classify(cert, now = new Date()) {
  if (cert.status === 'failed' || cert.status === 'pending' || cert.status === 'invalid') return cert.status;
  if (!cert.expiresAt) return 'unknown';
  const left = new Date(cert.expiresAt).getTime() - now.getTime();
  if (left <= 0) return 'expired';
  if (left <= RENEW_WINDOW_DAYS * DAY) return 'expiring';
  return 'valid';
}

export function createCertificatesService({ prisma, now = () => new Date(), auditService = null, rbac = null, platform = null, adapters = null, probe = probeTls, env = process.env }) {
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);
  const present = (c) => ({ ...c, state: classify(c, now()), daysLeft: c.expiresAt ? Math.floor((new Date(c.expiresAt) - now()) / DAY) : null });

  const scope = createScope({ prisma, now });

  async function loadDomain(domainId) {
    const d = await prisma.domain.findUnique({ where: { id: domainId } });
    if (!d || d.archivedAt) throw new AppError(404, 'DOMAIN_NOT_FOUND', 'Domain not found');
    return d;
  }
  async function authorize(actor, domain, environmentId) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    const env = await prisma.projectEnvironment.findUnique({ where: { id: environmentId } });
    if (!env || env.projectId !== domain.projectId) {
      throw new AppError(409, 'ENVIRONMENT_PROJECT_MISMATCH', 'Environment does not belong to this domain project');
    }
    await assertCan(rbac, actor, { permissionKey: PERM.SSL, resourceType: 'project', resourceId: domain.projectId, environmentId });
  }

  return {
    async list({ domainId, limit }, actor) {
      const domain = await scope.domainWhere(actor);
      const rows = await prisma.sslCertificate.findMany({ where: { ...(domainId ? { domainId } : {}), ...(Object.keys(domain).length ? { domain } : {}) }, take: limit, orderBy: { expiresAt: 'asc' } });
      return rows.map(present);
    },

    async expiring({ days }, actor) {
      const domain = await scope.domainWhere(actor);
      const rows = await prisma.sslCertificate.findMany({ where: { expiresAt: { lte: new Date(now().getTime() + days * DAY) }, ...(Object.keys(domain).length ? { domain } : {}) }, orderBy: { expiresAt: 'asc' } });
      return rows.map(present);
    },

    /** System scan: flips stale statuses to expired and buckets certificates for alerting. */
    async scanExpiry() {
      const rows = await prisma.sslCertificate.findMany({ where: { expiresAt: { not: null } } });
      const out = { expired: [], expiring: [], valid: 0 };
      for (const c of rows) {
        const state = classify(c, now());
        if (state === 'expired') {
          if (c.status !== 'expired') await prisma.sslCertificate.update({ where: { id: c.id }, data: { status: 'expired' } });
          out.expired.push(c.id);
          if (c.status !== 'expired') notifyChannels({ type: 'certificate.expiring', severity: 'critical', title: 'Certificate has expired', resourceType: 'certificate', resourceId: c.id, dedupeKey: `certificate.expired:${c.id}` }, { prisma });
        } else if (state === 'expiring') {
          out.expiring.push(c.id);
          notifyChannels({ type: 'certificate.expiring', severity: 'warning', title: 'Certificate is expiring soon', resourceType: 'certificate', resourceId: c.id, dedupeKey: `certificate.expiring:${c.id}` }, { prisma });
        } else if (state === 'valid') out.valid += 1;
      }
      return out;
    },

    /**
     * TASK-047: real expiry scan. Handshakes with each active domain that has a certificate record (CERT_EXPIRY_PROBE=1 enables
     * it in the job runners), stores the observed expiry, marks untrusted chains `invalid`, then runs the regular expiry
     * scan so the existing alerts fire. Probe failures keep the stored data and are only counted.
     */
    async scanLive({ limit = 200, probeOptions = {} } = {}) {
      const domains = await prisma.domain.findMany({ where: { archivedAt: null, status: 'active' }, take: limit, orderBy: { name: 'asc' } });
      const out = { probed: 0, updated: 0, invalid: [], unreachable: 0 };
      for (const d of domains) {
        const certs = await prisma.sslCertificate.findMany({ where: { domainId: d.id }, orderBy: { createdAt: 'desc' } });
        const cert = certs.find((c) => ['active', 'expiring', 'expired', 'invalid', 'renewal_failed'].includes(c.status));
        if (!cert) continue;
        const host = d.name.replace(/^\*\./, '');
        const res = await probe(host, probeOptions);
        out.probed += 1;
        if (!res.ok) {
          out.unreachable += 1;
          continue;
        }
        const status = res.trusted ? (res.validTo <= now() ? 'expired' : 'active') : 'invalid';
        await prisma.sslCertificate.update({ where: { id: cert.id }, data: { expiresAt: res.validTo, status, lastError: res.trusted ? null : String(res.authorizationError).slice(0, 190) } });
        out.updated += 1;
        if (!res.trusted) {
          out.invalid.push({ certificateId: cert.id, reason: res.authorizationError });
          notifyChannels({ type: 'certificate.expiring', severity: 'critical', title: 'Certificate chain is not trusted', resourceType: 'certificate', resourceId: cert.id, dedupeKey: `certificate.invalid:${cert.id}` }, { prisma });
        }
      }
      return { ...out, expiry: await this.scanExpiry() };
    },

    async issue(domainId, input, actor) {
      const domain = await loadDomain(domainId);
      await authorize(actor, domain, input.environmentId);
      if (input.wildcard && input.challenge !== 'dns-01') {
        throw new AppError(422, 'WILDCARD_NEEDS_DNS01', 'Wildcard certificates require the dns-01 challenge');
      }
      if (domain.status !== 'active') throw new AppError(409, 'DOMAIN_NOT_ACTIVE', 'Domain is not active');
      const dns = await adapters.dns.resolve(domain.name);
      if (!dns.resolves) throw new AppError(422, 'DNS_NOT_READY', 'Domain does not resolve yet');
      const impact = [`Issue ${input.wildcard ? 'wildcard ' : ''}certificate for ${domain.name} via ${input.challenge}`, 'Web server reload on success'];
      const gate = await platform.gate(
        { action: 'ssl.issue', binding: `${input.challenge}:${input.wildcard}`, resourceType: 'domain', resourceId: domainId, approvalId: input.approvalId, reason: input.reason, impact, rollbackPlan: input.rollbackNote, context: { environmentId: input.environmentId } },
        actor,
      );
      if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      const cert = await prisma.sslCertificate.create({ data: { domainId, status: 'pending', provider: null } });
      try {
        const res = await adapters.acme.issue({ domain: domain.name, challenge: input.challenge, wildcard: input.wildcard, serverId: domain.serverId ?? null });
        const saved = await prisma.sslCertificate.update({ where: { id: cert.id }, data: { status: 'active', provider: res.provider, expiresAt: res.expiresAt } });
        await audit({ actorId: actor.id, action: 'ssl.issue', resourceType: 'domain', resourceId: domainId, environmentId: input.environmentId, result: 'success', after: { certificateId: cert.id, expiresAt: res.expiresAt } });
        return { ...present(saved), simulated: adapters.acme.simulated ?? Boolean(adapters.simulated) };
      } catch {
        await prisma.sslCertificate.update({ where: { id: cert.id }, data: { status: 'failed' } });
        await audit({ actorId: actor.id, action: 'ssl.issue', resourceType: 'domain', resourceId: domainId, environmentId: input.environmentId, result: 'failure' });
        throw new AppError(502, 'ACME_ISSUE_FAILED', 'Certificate authority rejected the request');
      }
    },

    async renew(certId, input, actor) {
      const cert = await prisma.sslCertificate.findUnique({ where: { id: certId } });
      if (!cert) throw new AppError(404, 'CERT_NOT_FOUND', 'Certificate not found');
      const domain = await loadDomain(cert.domainId);
      await authorize(actor, domain, input.environmentId);
      const state = classify(cert, now());
      if (state === 'valid' && !input.force) throw new AppError(409, 'RENEWAL_NOT_DUE', `Renewal opens ${RENEW_WINDOW_DAYS} days before expiry`);
      if (state === 'failed' || state === 'pending') throw new AppError(409, 'CERT_NOT_RENEWABLE', 'Only issued certificates can be renewed');
      try {
        const res = await adapters.acme.issue({ domain: domain.name, challenge: 'http-01', renewal: true });
        const saved = await prisma.sslCertificate.update({ where: { id: certId }, data: { status: 'active', provider: res.provider, expiresAt: res.expiresAt } });
        await audit({ actorId: actor.id, action: 'ssl.renew', resourceType: 'domain', resourceId: domain.id, environmentId: input.environmentId, result: 'success', after: { certificateId: certId, expiresAt: res.expiresAt } });
        return present(saved);
      } catch {
        await prisma.sslCertificate.update({ where: { id: certId }, data: { status: state === 'expired' ? 'expired' : 'renewal_failed' } });
        await audit({ actorId: actor.id, action: 'ssl.renew', resourceType: 'domain', resourceId: domain.id, environmentId: input.environmentId, result: 'failure' });
        throw new AppError(502, 'ACME_RENEW_FAILED', 'Renewal failed; the previous certificate is unchanged');
      }
    },
  };
}
