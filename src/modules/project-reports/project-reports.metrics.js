/** Pure aggregation helpers for project reports. No I/O. */

export const DAY_MS = 86400000;

export const round = (n, d = 1) => (n == null || Number.isNaN(n) ? null : Math.round(n * 10 ** d) / 10 ** d);

/** Nearest-rank percentile over unsorted numbers. Returns null for an empty list. */
export function percentile(values, p) {
  const v = values.filter((x) => Number.isFinite(x)).sort((a, b) => a - b);
  if (!v.length) return null;
  const rank = Math.ceil((p / 100) * v.length);
  return v[Math.min(v.length - 1, Math.max(0, rank - 1))];
}

export const median = (values) => percentile(values, 50);

export const rate = (num, den) => (den > 0 ? round((num / den) * 100, 1) : null);

/** Percentage change vs previous period; null when the previous value is missing or zero (and current non-zero). */
export function deltaPct(current, previous) {
  if (current == null || previous == null) return null;
  if (previous === 0) return current === 0 ? 0 : null;
  return round(((current - previous) / Math.abs(previous)) * 100, 1);
}

export const dayKey = (d) => new Date(d).toISOString().slice(0, 10);

/** Monday (UTC) of the week containing the date. */
export function weekKey(d) {
  const x = new Date(dayKey(d) + 'T00:00:00Z');
  const dow = (x.getUTCDay() + 6) % 7;
  return dayKey(new Date(x.getTime() - dow * DAY_MS));
}

export const bucketKey = (d, granularity) => (granularity === 'week' ? weekKey(d) : dayKey(d));

/** Continuous list of bucket keys covering [from, to). */
export function bucketKeys(from, to, granularity) {
  const keys = [];
  const step = granularity === 'week' ? 7 * DAY_MS : DAY_MS;
  let t = new Date(bucketKey(from, granularity) + 'T00:00:00Z').getTime();
  while (t < new Date(to).getTime() && keys.length < 400) {
    keys.push(dayKey(new Date(t)));
    t += step;
  }
  return keys;
}

const norm = (s) => String(s ?? '').toLowerCase().replace(/[\s_-]/g, '');
export const isSuccess = (s) => ['success', 'succeeded', 'completed', 'ok', 'passed', 'verified'].includes(norm(s));
export const isFailure = (s) => ['failed', 'failure', 'error', 'timeout', 'timedout'].includes(norm(s));
export const isRolledBack = (s) => norm(s) === 'rolledback';

export function countBy(items, keyFn) {
  const m = new Map();
  for (const it of items) {
    const k = keyFn(it);
    if (k == null) continue;
    m.set(k, (m.get(k) ?? 0) + 1);
  }
  return [...m.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count || String(a.key).localeCompare(String(b.key)));
}

/** Whole days from a to b, floored; null when either is absent. */
export function daysBetween(a, b) {
  if (!a || !b) return null;
  return Math.floor((new Date(b).getTime() - new Date(a).getTime()) / DAY_MS);
}

/**
 * Explainable health score. Each factor earns `score` of `weight`; unavailable factors are excluded
 * so missing data never inflates or deflates the result.
 */
export function computeScore(f, now) {
  const factors = [];
  const add = (key, label, weight, earned, detail, available = true) =>
    factors.push({
      key,
      label,
      weight,
      score: available ? round(Math.max(0, Math.min(weight, earned)), 1) : null,
      available,
      detail,
    });

  const d = f.deployments;
  add(
    'deploy_success',
    'Deployment success rate',
    25,
    d.total ? (d.successRate / 100) * 25 : 0,
    d.total ? `${d.successRate}% of ${d.total} deployments succeeded` : 'No deployments in range',
    d.total > 0,
  );
  add(
    'uptime',
    'Uptime',
    25,
    f.uptime.pct == null ? 0 : 25 - Math.min(25, (100 - f.uptime.pct) * 5),
    f.uptime.pct == null ? 'No uptime checks in range' : `${f.uptime.pct}% of ${f.uptime.checks} checks passed`,
    f.uptime.pct != null,
  );

  let b = 15;
  let bd = 'Recent verified backup';
  if (!f.backups.policies) {
    b = 5;
    bd = 'No backup policy configured';
  } else if (f.backups.lastSuccessDays == null || f.backups.lastSuccessDays > 7) {
    b = 0;
    bd = f.backups.lastSuccessDays == null ? 'No successful backup recorded' : `Last successful backup ${f.backups.lastSuccessDays} days ago`;
  } else if (f.backups.lastVerifiedDays == null || f.backups.lastVerifiedDays > 30) {
    b = 10;
    bd = 'Backups run but none verified in 30 days';
  }
  add('backups', 'Backups and recovery', 15, b, bd, true);

  const cd = f.certificates.minDaysLeft;
  add(
    'certificates',
    'Certificate expiry',
    10,
    cd == null ? 0 : cd < 0 ? 0 : cd < 7 ? 2 : cd < 14 ? 5 : 10,
    cd == null ? 'No certificates tracked' : `Next expiry in ${cd} days`,
    cd != null,
  );

  const inc = f.incidents;
  add(
    'incidents',
    'Incidents and alerts',
    15,
    15 - Math.min(15, inc.critical * 6 + inc.total * 2 + f.alerts.critical * 2 + inc.open * 4),
    `${inc.total} incidents (${inc.open} open), ${f.alerts.total} alerts`,
    true,
  );

  const errPerDay = f.logs.errors / Math.max(1, f.rangeDays);
  add(
    'errors',
    'Error volume',
    10,
    f.logs.available ? 10 - Math.min(10, Math.log10(1 + errPerDay) * 5) : 0,
    f.logs.available ? `${f.logs.errors} errors, ${round(errPerDay)} per day` : 'No log entries ingested',
    f.logs.available,
  );

  const avail = factors.filter((x) => x.available);
  const totalW = avail.reduce((n, x) => n + x.weight, 0);
  const earned = avail.reduce((n, x) => n + x.score, 0);
  let score = totalW ? Math.round((earned / totalW) * 100) : null;
  const stale = f.deployments.lastDays;
  let penalty = 0;
  if (score != null && stale != null && stale > 60) {
    penalty = Math.min(5, score);
    score -= penalty;
  }
  const grade = score == null ? 'unknown' : score >= 85 ? 'healthy' : score >= 65 ? 'attention' : 'at_risk';
  return { score, grade, factors, stalePenalty: penalty, computedAt: new Date(now).toISOString() };
}

/** Concrete, ordered recommendations derived from computed facts. */
export function buildRecommendations(f) {
  const out = [];
  const rec = (id, severity, title, detail, hint) => out.push({ id, severity, title, detail, hint });
  if (!f.backups.policies) rec('backup_policy_missing', 'high', 'No backup policy', 'This project has no backup policy.', 'Create a backup policy under Backups.');
  else if (f.backups.lastSuccessDays == null || f.backups.lastSuccessDays > 7)
    rec(
      'backup_stale',
      'high',
      f.backups.lastSuccessDays == null ? 'No successful backup yet' : `No successful backup in ${f.backups.lastSuccessDays} days`,
      'Recovery points are stale.',
      'Run a backup now and check the schedule.',
    );
  else if (f.backups.lastVerifiedDays == null || f.backups.lastVerifiedDays > 30)
    rec('backup_unverified', 'medium', 'No verified backup restore in 30 days', 'Backups that are never verified may not restore.', 'Run a restore verification in an isolated trial.');
  const cd = f.certificates.minDaysLeft;
  if (cd != null && cd < 14)
    rec('cert_expiring', cd < 7 ? 'critical' : 'high', cd < 0 ? 'A certificate has expired' : `Certificate expires in ${cd} days`, 'Expired certificates break HTTPS.', 'Renew it from Domains and SSL.');
  if (f.uptime.monitors === 0) rec('no_uptime_check', 'medium', 'No uptime check configured', 'Availability cannot be measured.', 'Add an uptime monitor for the public URL.');
  else if (f.uptime.pct != null && f.uptime.pct < 99)
    rec('uptime_low', f.uptime.pct < 95 ? 'high' : 'medium', `Uptime is ${f.uptime.pct}%`, 'Checks failed during the period.', 'Review the incident timeline and failing URL.');
  const topStep = f.failuresByStep[0];
  if (topStep && topStep.count >= 2)
    rec('repeated_step_failure', 'high', `Step "${topStep.key}" failed ${topStep.count} times`, 'The same deployment step keeps failing.', 'Open the failing deployment steps and fix the root cause.');
  if (f.deployments.total > 0 && f.deployments.successRate < 80)
    rec('deploy_success_low', 'high', `Deployment success rate is ${f.deployments.successRate}%`, 'More than one in five deployments failed.', 'Add pre-deploy checks or enable approvals.');
  if (f.deployments.lastDays != null && f.deployments.lastDays > 60)
    rec('stale_deploy', 'low', `Last deployment was ${f.deployments.lastDays} days ago`, 'Dependencies and security fixes may be pending.', 'Schedule a maintenance deployment.');
  if (f.incidents.open > 0) rec('open_incidents', 'high', `${f.incidents.open} incident(s) still open`, 'Open incidents lower the score.', 'Triage and close them from Incidents.');
  if (f.alerts.openCritical > 0) rec('open_critical_alerts', 'high', `${f.alerts.openCritical} critical alert(s) open`, 'Critical alerts are unresolved.', 'Acknowledge or resolve them from Monitoring.');
  if (f.logs.available && f.logs.errors / Math.max(1, f.rangeDays) > 50)
    rec('error_volume', 'medium', 'High error log volume', `${f.logs.errors} errors in range.`, 'Inspect the top error fingerprints.');
  if (!f.domains.total) rec('no_domain', 'low', 'No domain attached', 'The project has no domain.', 'Attach a domain under Domains.');
  if (f.cron.total > 0 && f.cron.successRate != null && f.cron.successRate < 90)
    rec('cron_failing', 'medium', `Cron success rate is ${f.cron.successRate}%`, 'Scheduled jobs are failing.', 'Open Cron and inspect recent run output.');
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  return out.sort((a, b) => order[a.severity] - order[b.severity]);
}

const FORMULA = /^[=+\-@\t\r]/;

/** CSV cell with RFC 4180 quoting and a spreadsheet formula-injection guard. */
export function csvCell(v) {
  if (v == null) return '';
  let s = typeof v === 'object' ? JSON.stringify(v) : String(v);
  if (typeof v !== 'number' && FORMULA.test(s)) s = "'" + s;
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

export function toCsv(columns, rows) {
  const lines = [columns.map(csvCell).join(',')];
  for (const r of rows) lines.push(columns.map((c) => csvCell(r[c])).join(','));
  return lines.join('\r\n') + '\r\n';
}
