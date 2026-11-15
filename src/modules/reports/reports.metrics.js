export const REPORT_TYPES = [
  'project-summary',
  'individual-activity',
  'project-contribution',
  'deployment-success',
  'changes',
  'incidents',
  'security',
  'failed-operations',
  'workload',
  'access',
];

const FAILED = ['FAILED', 'TIMEOUT', 'DENIED', 'EXPIRED'];
const LINEAGE_CAP = 100;

const uniqueById = (rows) => [...new Map(rows.map((r) => [r.id, r])).values()];
const ref = (source) => (row) => ({ source, id: row.id });
const lineageOf = (source, rows) => {
  const refs = uniqueById(rows).map(ref(source));
  return { lineage: refs.slice(0, LINEAGE_CAP), lineageTotal: refs.length };
};
const metric = (key, label, rows, source, unit = 'count') => ({
  key, label, unit, value: uniqueById(rows).length, ...lineageOf(source, rows),
});
/** A ratio with a zero denominator is N/A (null), never 0 or NaN. */
const ratio = (key, label, numRows, denRows, source) => {
  const den = uniqueById(denRows).length;
  const num = uniqueById(numRows).length;
  return {
    key, label, unit: 'percent', value: den === 0 ? null : Math.round((num / den) * 1000) / 10,
    display: den === 0 ? 'N/A' : `${Math.round((num / den) * 1000) / 10}%`,
    numerator: num, denominator: den, ...lineageOf(source, denRows),
  };
};
const group = (rows, keyFn, source, labelFn = (k) => k) => {
  const m = new Map();
  for (const r of uniqueById(rows)) {
    const k = keyFn(r) ?? 'unknown';
    m.set(k, [...(m.get(k) ?? []), r]);
  }
  return [...m.entries()]
    .map(([k, list]) => ({ key: k, label: labelFn(k), value: list.length, ...lineageOf(source, list) }))
    .sort((a, b) => b.value - a.value || String(a.key).localeCompare(String(b.key)));
};

const inPeriod = (d, from, to) => {
  if (!d) return false;
  const t = new Date(d).getTime();
  return (!from || t >= from.getTime()) && (!to || t < to.getTime());
};

const isConfig = (a) => a.result !== 'denied' && /^(project\.(configure|create|link|archive|discover)|domain\.|ssl\.)/.test(a.action);

/**
 * Pure aggregation over collected facts. Every metric and breakdown row carries `lineage`, the list of
 * original source rows (source + id) it was computed from, so each number can be opened and recomputed.
 * Rows are de-duplicated by id: retries create new executions, not new operations or deployments.
 */
export function buildReport(type, facts, { from, to, userId = null, projectId = null, label = (id) => id } = {}) {
  if (!REPORT_TYPES.includes(type)) throw new Error(`Unknown report type ${type}`);
  const ops = uniqueById(facts.operations);
  const deps = uniqueById(facts.deployments);
  const apps = uniqueById(facts.approvals);
  const audits = uniqueById(facts.audits);
  const failedOps = ops.filter((o) => FAILED.includes(o.status));
  const denials = audits.filter((a) => a.result === 'denied');
  const changes = audits.filter(isConfig);
  const grants = uniqueById(facts.grants);
  const grantedIn = grants.filter((g) => inPeriod(g.createdAt, from, to));
  const revokedIn = grants.filter((g) => g.revokedAt && inPeriod(g.revokedAt, from, to));
  const activeAtEnd = grants.filter(
    (g) =>
      (!to || new Date(g.createdAt) < to) &&
      (!g.revokedAt || (to && new Date(g.revokedAt) >= to)) &&
      (!g.expiresAt || !to || new Date(g.expiresAt) > to),
  );
  const incidents = uniqueById(facts.incidents);
  const sec = uniqueById(facts.securityEvents);
  const success = deps.filter((d) => d.status === 'Success');
  const rolledBack = deps.filter((d) => d.status === 'Rolled Back');
  const failedDeps = deps.filter((d) => d.status === 'Failed');
  const users = (key) => (r) => r[key];
  const metrics = [];
  const breakdowns = [];

  const deploymentMetrics = () => [
    metric('deployments.total', 'Deployments', deps, 'deployment'),
    metric('deployments.success', 'Successful deployments', success, 'deployment'),
    metric('deployments.failed', 'Failed deployments', failedDeps, 'deployment'),
    metric('deployments.rolledBack', 'Rolled back deployments', rolledBack, 'deployment'),
    ratio('deployments.successRate', 'Deployment success rate', success, deps, 'deployment'),
  ];

  switch (type) {
    case 'deployment-success':
      metrics.push(...deploymentMetrics());
      breakdowns.push({ key: 'byEnvironment', label: 'Deployments by environment', rows: group(deps, (d) => d.environmentId, 'deployment') });
      break;
    case 'failed-operations':
      metrics.push(metric('operations.total', 'Operations', ops, 'operation'), metric('operations.failed', 'Failed operations', failedOps, 'operation'));
      metrics.push(ratio('operations.failureRate', 'Operation failure rate', failedOps, ops, 'operation'));
      breakdowns.push(
        { key: 'byStatus', label: 'Failures by status', rows: group(failedOps, (o) => o.status, 'operation') },
        { key: 'byAction', label: 'Failures by action', rows: group(failedOps, (o) => o.action, 'operation') },
      );
      break;
    case 'changes':
      metrics.push(metric('changes.total', 'Configuration changes', changes, 'audit'));
      breakdowns.push({ key: 'byAction', label: 'Changes by action', rows: group(changes, (a) => a.action, 'audit') });
      break;
    case 'incidents':
      metrics.push(metric('incidents.assigned', 'Incident assignments', incidents, 'incident'));
      breakdowns.push({ key: 'byMember', label: 'Assignments by member', rows: group(incidents, users('userId'), 'incident', label) });
      break;
    case 'security':
      metrics.push(metric('security.events', 'Security events', sec, 'security'), metric('security.denials', 'Denied operations', denials, 'audit'));
      breakdowns.push(
        { key: 'bySeverity', label: 'Events by severity', rows: group(sec, (s) => s.severity, 'security') },
        { key: 'byCategory', label: 'Events by category', rows: group(sec, (s) => s.category, 'security') },
      );
      break;
    case 'workload':
      metrics.push(metric('operations.total', 'Operations', ops, 'operation'));
      breakdowns.push(
        { key: 'initiated', label: 'Operations initiated by member', rows: group(ops, users('initiatorId'), 'operation', label) },
        { key: 'approvedBy', label: 'Operations approved by member', rows: group(ops.filter((o) => o.approverId), users('approverId'), 'operation', label) },
        { key: 'incidents', label: 'Incident assignments by member', rows: group(incidents, users('userId'), 'incident', label) },
      );
      break;
    case 'access':
      metrics.push(
        metric('grants.created', 'Grants created in period', grantedIn, 'grant'),
        metric('grants.revoked', 'Grants revoked in period', revokedIn, 'grant'),
        metric('grants.active', 'Active grants at period end', activeAtEnd, 'grant'),
      );
      breakdowns.push({ key: 'activeByMember', label: 'Active grants by member', rows: group(activeAtEnd, users('userId'), 'grant', label) });
      break;
    case 'project-contribution': {
      const total = deps.length + apps.filter((a) => a.approverId).length + changes.length;
      metrics.push(
        metric('deployments.total', 'Deployments', deps, 'deployment'),
        metric('approvals.decided', 'Approvals decided', apps.filter((a) => a.approverId), 'approval'),
        metric('changes.total', 'Configuration changes', changes, 'audit'),
        { key: 'contribution.events', label: 'Contribution events', unit: 'count', value: total, lineage: [], lineageTotal: 0 },
      );
      breakdowns.push(
        { key: 'deploymentsByMember', label: 'Deployments initiated by member', rows: group(deps, (d) => d.initiatedById, 'deployment', label) },
        { key: 'approvalsByMember', label: 'Approvals decided by member', rows: group(apps.filter((a) => a.approverId), users('approverId'), 'approval', label) },
        { key: 'changesByMember', label: 'Changes by member', rows: group(changes, (a) => a.actorId, 'audit', label) },
      );
      break;
    }
    case 'individual-activity': {
      const u = userId;
      metrics.push(
        metric('deployments.initiated', 'Deployments initiated', deps.filter((d) => d.initiatedById === u), 'deployment'),
        metric('operations.initiated', 'Operations initiated', ops.filter((o) => o.initiatorId === u), 'operation'),
        metric('operations.approved', 'Operations approved', ops.filter((o) => o.approverId === u), 'operation'),
        metric('approvals.decided', 'Approvals decided', apps.filter((a) => a.approverId === u), 'approval'),
        metric('operations.failed', 'Failed operations initiated', failedOps.filter((o) => o.initiatorId === u), 'operation'),
        metric('denials', 'Denied actions', denials.filter((a) => a.actorId === u), 'audit'),
        metric('changes.total', 'Configuration changes', changes.filter((a) => a.actorId === u), 'audit'),
        metric('grants.given', 'Grants given', grantedIn.filter((g) => g.grantedById === u), 'grant'),
        metric('incidents.assigned', 'Incident assignments', incidents.filter((i) => i.userId === u), 'incident'),
        ratio('deployments.successRate', 'Success rate of own deployments', success.filter((d) => d.initiatedById === u), deps.filter((d) => d.initiatedById === u), 'deployment'),
      );
      break;
    }
    default: // project-summary
      metrics.push(
        ...deploymentMetrics(),
        metric('operations.failed', 'Failed operations', failedOps, 'operation'),
        metric('approvals.pending', 'Pending approvals', apps.filter((a) => a.status === 'PENDING'), 'approval'),
        metric('denials', 'Denied actions', denials, 'audit'),
        metric('changes.total', 'Configuration changes', changes, 'audit'),
        metric('security.events', 'Security events', sec, 'security'),
      );
      breakdowns.push({ key: 'deploymentsByEnvironment', label: 'Deployments by environment', rows: group(deps, (d) => d.environmentId, 'deployment') });
  }

  return {
    type,
    period: { from: from?.toISOString() ?? null, to: to?.toISOString() ?? null, boundary: 'from inclusive, to exclusive' },
    scope: { projectId, userId },
    metrics,
    breakdowns,
    notes: [
      'Metrics count platform events only; no device activity or keystrokes.',
      'Error or failure timing does not prove who caused it.',
    ],
  };
}
