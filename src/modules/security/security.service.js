import { redact } from '../audit/audit.service.js';
import { createScope } from '../../common/scope.js';
import { assertCan } from '../platform/platform.service.js';
import { PERM } from '../platform/platform.risk.js';

export const COVERAGE_NOTICE = 'Wazuh signals are indicators only. NodeTeam does not guarantee detection of every compromise.';
const DAY = 86400000;

export function severityFromLevel(level) {
  if (level >= 12) return 'critical';
  if (level >= 9) return 'high';
  if (level >= 6) return 'medium';
  return 'low';
}

const CATEGORY_RULES = [
  ['authentication', /authentication|sshd|ssh|pam|login/],
  ['sudo', /sudo/],
  ['sessions', /session/],
  ['firewall', /firewall|iptables|ufw/],
  ['ports', /port/],
  ['services', /service|systemd/],
  ['fim', /syscheck|fim|integrity/],
  ['updates', /update|vulnerab|package/],
  ['malware', /rootcheck|malware|virus|trojan/],
];

export function categorize(groups = []) {
  const text = groups.join(' ').toLowerCase();
  return CATEGORY_RULES.find(([, re]) => re.test(text))?.[0] ?? 'other';
}

/** Normalise one Wazuh alert. Raw payload is redacted and truncated before storage. */
export function normalizeAlert(alert) {
  const level = Number(alert?.rule?.level ?? 0);
  return {
    wazuhId: String(alert.id),
    severity: severityFromLevel(level),
    category: categorize(alert?.rule?.groups ?? []),
    occurredAt: new Date(alert.timestamp),
    agentName: alert?.agent?.name ?? null,
    payload: redact({
      wazuhId: String(alert.id),
      ruleLevel: level,
      description: String(alert?.rule?.description ?? '').slice(0, 300),
      groups: (alert?.rule?.groups ?? []).slice(0, 10),
      data: alert.data ? (JSON.stringify(alert.data).length > 2000 ? { truncated: true } : alert.data) : undefined,
      independent: true,
    }),
  };
}

function safeData(alert) {
  try {
    return normalizeAlert(alert);
  } catch {
    return normalizeAlert({ ...alert, data: undefined });
  }
}

export function createSecurityService({ prisma, now = () => new Date(), auditService = null, rbac = null, adapters = null, incidents = null }) {
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);
  const scope = createScope({ prisma, now });

  return {
    async listIncidents({ status, limit }, actor) {
      const projectId = await scope.projectClause(actor);
      return prisma.securityIncident.findMany({ where: { ...(status ? { status } : {}), ...(projectId ? { projectId } : {}) }, take: limit, orderBy: { updatedAt: 'desc' }, include: { assignments: true } });
    },

    async listEvents({ serverId, severity, category, limit }, actor) {
      const serverClause = await scope.serverClause(actor, serverId);
      return prisma.securityEvent.findMany({
        where: { ...(serverClause ? { serverId: serverClause } : {}), ...(severity ? { severity } : {}), ...(category ? { category } : {}) },
        take: limit,
        orderBy: { occurredAt: 'desc' },
      });
    },

    async summary(actor) {
      const since = new Date(now().getTime() - DAY);
      const serverClause = await scope.serverClause(actor);
      const events = await prisma.securityEvent.findMany({ where: { occurredAt: { gte: since }, ...(serverClause ? { serverId: serverClause } : {}) }, take: 5000 });
      const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
      const byCategory = {};
      for (const e of events) {
        bySeverity[e.severity] = (bySeverity[e.severity] ?? 0) + 1;
        byCategory[e.category] = (byCategory[e.category] ?? 0) + 1;
      }
      return { windowHours: 24, total: events.length, bySeverity, byCategory, notice: COVERAGE_NOTICE };
    },

    /** Source health. An unreachable Wazuh is reported, never hidden or treated as "no threats". */
    async connection() {
      try {
        const h = await adapters.wazuh.health();
        return { connected: Boolean(h.connected), simulated: Boolean(adapters.simulated), notice: COVERAGE_NOTICE };
      } catch {
        return { connected: false, reason: 'source_unavailable', notice: COVERAGE_NOTICE };
      }
    },

    /** Pull and store alerts. Source failure degrades to a status; stored events are untouched. */
    async sync({ sinceMinutes }, actor) {
      await assertCan(rbac, actor, { permissionKey: PERM.INCIDENT, resourceType: 'platform', resourceId: 'platform', environmentId: null });
      const since = new Date(now().getTime() - sinceMinutes * 60000);
      let alerts;
      try {
        alerts = await adapters.wazuh.fetchAlerts({ since });
      } catch {
        await audit({ actorId: actor.id, action: 'security.sync', resourceType: 'wazuh', result: 'failure', metadata: { reason: 'source_unavailable' } });
        return { status: 'source_unavailable', ingested: 0, duplicates: 0, notice: COVERAGE_NOTICE };
      }
      let ingested = 0;
      let duplicates = 0;
      let opened = 0;
      for (const alert of alerts) {
        if (!alert?.id || !alert.timestamp || Number.isNaN(Date.parse(alert.timestamp))) continue;
        const n = safeData(alert);
        const dup = await prisma.securityEvent.findFirst({ where: { source: 'wazuh', payloadJson: { path: '$.wazuhId', equals: n.wazuhId } } });
        if (dup) {
          duplicates += 1;
          continue;
        }
        const server = n.agentName ? await prisma.server.findFirst({ where: { alias: n.agentName } }) : null;
        const event = await prisma.securityEvent.create({
          data: { serverId: server?.id ?? null, severity: n.severity, category: n.category, occurredAt: n.occurredAt, source: 'wazuh', payloadJson: { ...n.payload, unmappedAgent: n.agentName && !server ? true : undefined } },
        });
        ingested += 1;
        if (incidents && (n.severity === 'critical' || n.severity === 'high')) {
          await incidents.openFromEvent({ event, title: `${n.category}: ${n.payload.description || 'Wazuh alert'}`.slice(0, 200) });
          opened += 1;
        }
      }
      await audit({ actorId: actor.id, action: 'security.sync', resourceType: 'wazuh', result: 'success', metadata: { ingested, duplicates, opened } });
      return { status: 'ok', ingested, duplicates, incidentsTouched: opened, notice: COVERAGE_NOTICE };
    },
  };
}
