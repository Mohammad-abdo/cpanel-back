import { describe, expect, it, vi } from 'vitest';
import { INCIDENT_TRANSITIONS, REOPEN_WINDOW_MS, createIncidentsService } from '../src/modules/incidents/incidents.service.js';
import { createSecurityService, normalizeAlert, severityFromLevel } from '../src/modules/security/security.service.js';
import { createAuditService } from '../src/modules/audit/audit.service.js';
import { createSimulatedAdapters } from '../src/modules/platform/platform.adapters.js';
import { APPROVER, DEV, OWNER, U, makeRbac } from './phase6-helpers.js';

let clock = new Date('2026-06-01T00:00:00Z');
const now = () => new Date(clock);
const tick = (ms = 1000) => { clock = new Date(clock.getTime() + ms); };

function incidentsSetup() {
  const incs = new Map();
  const assigns = [];
  const audits = [];
  let n = 0;
  const prisma = {
    securityIncident: {
      create: vi.fn(async ({ data }) => { const r = { id: U(100 + ++n), createdAt: now(), ...data }; incs.set(r.id, r); return r; }),
      findUnique: vi.fn(async ({ where }) => { const r = incs.get(where.id); return r ? { ...r, assignments: assigns.filter((a) => a.incidentId === r.id) } : null; }),
      findFirst: vi.fn(async ({ where }) => [...incs.values()].find((r) => r.title === where.title && r.status !== 'closed') ?? null),
      update: vi.fn(async ({ where, data }) => Object.assign(incs.get(where.id), data)),
      findMany: vi.fn(async () => [...incs.values()]),
    },
    incidentAssignment: { create: vi.fn(async ({ data }) => { tick(); const a = { ...data, assignedAt: now() }; assigns.push(a); return a; }) },
    user: { findUnique: vi.fn(async ({ where }) => ({ id: where.id, status: where.id === U(66) ? 'disabled' : 'active', disabledAt: null })) },
    auditEvent: {
      create: vi.fn(async ({ data }) => { tick(); audits.push({ ...data, id: String(audits.length) }); return data; }),
      findMany: vi.fn(async ({ where, orderBy, take }) => {
        let rows = audits.filter((a) => a.resourceType === where.resourceType && a.resourceId === where.resourceId && (!where.action || a.action === where.action));
        rows = rows.sort((a, b) => (orderBy.occurredAt === 'desc' ? b.occurredAt - a.occurredAt : a.occurredAt - b.occurredAt));
        return take ? rows.slice(0, take) : rows;
      }),
    },
  };
  const auditService = createAuditService({ prisma, now });
  const manager = { userId: DEV.id, permissionKey: 'security.incident.manage', resourceId: 'platform', environmentId: null };
  const other = { userId: APPROVER.id, permissionKey: 'security.incident.manage', resourceId: 'platform', environmentId: null };
  const rbac = makeRbac([manager, other]);
  return { prisma, audits, assigns, svc: createIncidentsService({ prisma, now, auditService, rbac }), incs };
}

async function driveTo(t, state, actor = DEV) {
  const inc = await t.svc.create({ title: 'Suspicious sudo usage', severity: 'high' }, actor);
  const path = ['detected', 'triaged', 'assigned', 'investigating', 'contained', 'resolved', 'closed'];
  for (let i = 1; i <= path.indexOf(state); i += 1) {
    if (path[i] === 'assigned') await t.svc.assign(inc.id, { userId: actor.id }, actor);
    else await t.svc.transition(inc.id, { to: path[i], note: 'step ok' }, actor);
  }
  return inc;
}

describe('incidents: lifecycle', () => {
  it('walks the full lifecycle and records timestamps', async () => {
    const t = incidentsSetup();
    const inc = await driveTo(t, 'closed');
    expect(t.incs.get(inc.id).status).toBe('closed');
    expect(t.incs.get(inc.id).closedAt).toBeInstanceOf(Date);
    const tl = await t.svc.timeline(inc.id, OWNER);
    expect(tl.filter((e) => e.action === 'incident.transition').every((e) => e.afterJson.at)).toBe(true);
    expect(tl.find((e) => e.action === 'incident.assign').afterJson.ownerId).toBe(DEV.id);
  });
  it('rejects invalid transitions (skip, backwards from closed)', async () => {
    const t = incidentsSetup();
    const inc = await t.svc.create({ title: 'Brute force on ssh', severity: 'medium' }, DEV);
    await expect(t.svc.transition(inc.id, { to: 'investigating' }, DEV)).rejects.toMatchObject({ code: 'INVALID_INCIDENT_TRANSITION' });
    await expect(t.svc.transition(inc.id, { to: 'closed', note: 'x12' }, DEV)).rejects.toMatchObject({ code: 'INVALID_INCIDENT_TRANSITION' });
    expect(INCIDENT_TRANSITIONS.closed).toEqual([]);
    const done = await driveTo(t, 'closed');
    await expect(t.svc.transition(done.id, { to: 'investigating' }, DEV)).rejects.toMatchObject({ code: 'INVALID_INCIDENT_TRANSITION' });
  });
  it('requires a real, active assignee and a resolution note', async () => {
    const t = incidentsSetup();
    const inc = await t.svc.create({ title: 'Malware signature hit', severity: 'high' }, DEV);
    await t.svc.transition(inc.id, { to: 'triaged' }, DEV);
    await expect(t.svc.assign(inc.id, { userId: U(66) }, DEV)).rejects.toMatchObject({ code: 'ASSIGNEE_INVALID' });
    await expect(t.svc.transition(inc.id, { to: 'assigned' }, DEV)).rejects.toMatchObject({ code: 'USE_ASSIGN' });
    await t.svc.assign(inc.id, { userId: DEV.id }, DEV);
    for (const s of ['investigating', 'resolved']) await t.svc.transition(inc.id, { to: s }, DEV);
    await expect(t.svc.transition(inc.id, { to: 'closed' }, DEV)).rejects.toMatchObject({ code: 'RESOLUTION_NOTE_REQUIRED' });
  });
  it('cannot assign before triage', async () => {
    const t = incidentsSetup();
    const inc = await t.svc.create({ title: 'Open port 3306 exposed', severity: 'low' }, DEV);
    await expect(t.svc.assign(inc.id, { userId: DEV.id }, DEV)).rejects.toMatchObject({ code: 'INVALID_INCIDENT_TRANSITION' });
  });
  it('enforces ownership and permission', async () => {
    const t = incidentsSetup();
    const inc = await driveTo(t, 'investigating');
    await expect(t.svc.transition(inc.id, { to: 'contained' }, APPROVER)).rejects.toMatchObject({ code: 'NOT_INCIDENT_OWNER' });
    await expect(t.svc.transition(inc.id, { to: 'contained' }, { id: U(9), isOwner: false })).rejects.toMatchObject({ status: 403 });
    await expect(t.svc.create({ title: 'Anything at all', severity: 'low' }, { id: U(9), isOwner: false })).rejects.toMatchObject({ status: 403 });
    await expect(t.svc.transition(inc.id, { to: 'contained' }, OWNER)).resolves.toBeTruthy();
  });
  it('preserves severity across transitions and only escalates upward', async () => {
    const t = incidentsSetup();
    const inc = await driveTo(t, 'investigating');
    expect(t.incs.get(inc.id).severity).toBe('high');
    await expect(t.svc.escalate(inc.id, { severity: 'medium', reason: 'downgrade' }, DEV)).rejects.toMatchObject({ code: 'SEVERITY_NOT_HIGHER' });
    await t.svc.escalate(inc.id, { severity: 'critical', reason: 'lateral movement seen' }, DEV);
    expect(t.incs.get(inc.id).severity).toBe('critical');
    const e = (await t.svc.timeline(inc.id, OWNER)).find((x) => x.action === 'incident.escalate');
    expect(e.beforeJson.severity).toBe('high');
  });
  it('critical incidents are closed only by the Owner', async () => {
    const t = incidentsSetup();
    const inc = await driveTo(t, 'resolved');
    await t.svc.escalate(inc.id, { severity: 'critical', reason: 'confirmed breach' }, DEV);
    await expect(t.svc.transition(inc.id, { to: 'closed', note: 'done' }, DEV)).rejects.toMatchObject({ code: 'OWNER_CLOSE_REQUIRED' });
    await expect(t.svc.transition(inc.id, { to: 'closed', note: 'done' }, OWNER)).resolves.toBeTruthy();
  });
  it('reopen policy: within 14 days only, by owner, preserving the close record', async () => {
    const t = incidentsSetup();
    const inc = await driveTo(t, 'closed');
    await expect(t.svc.reopen(inc.id, { reason: 'recurred' }, APPROVER)).rejects.toMatchObject({ code: 'NOT_INCIDENT_OWNER' });
    await t.svc.reopen(inc.id, { reason: 'recurred same day' }, DEV);
    expect(t.incs.get(inc.id).status).toBe('investigating');
    const ev = (await t.svc.timeline(inc.id, OWNER)).find((x) => x.action === 'incident.reopen');
    expect(ev.beforeJson.closedAt).toBeTruthy();
    const late = await driveTo(t, 'closed');
    clock = new Date(clock.getTime() + REOPEN_WINDOW_MS + 1000);
    await expect(t.svc.reopen(late.id, { reason: 'too late' }, DEV)).rejects.toMatchObject({ code: 'REOPEN_WINDOW_EXPIRED' });
    await expect(t.svc.reopen((await driveTo(t, 'investigating')).id, { reason: 'not closed' }, DEV)).rejects.toMatchObject({ code: 'NOT_CLOSED' });
  });
});

describe('incidents: evidence', () => {
  it('chains evidence, redacts secrets and detects tampering', async () => {
    const t = incidentsSetup();
    const inc = await driveTo(t, 'investigating');
    await t.svc.addEvidence(inc.id, { type: 'command_output', summary: 'curl -H "x" password=hunter2 token: abc123' }, DEV);
    await t.svc.addEvidence(inc.id, { type: 'note', summary: 'second observation' }, DEV);
    expect(JSON.stringify(t.audits)).not.toContain('hunter2');
    expect(JSON.stringify(t.audits)).not.toContain('abc123');
    expect(await t.svc.verifyEvidence(inc.id, OWNER)).toEqual({ intact: true, count: 2 });
    const first = t.audits.find((a) => a.action === 'incident.evidence');
    first.afterJson = { ...first.afterJson, summary: 'edited later' };
    expect((await t.svc.verifyEvidence(inc.id, OWNER)).intact).toBe(false);
  });
  it('refuses evidence on closed incidents and from non-owners', async () => {
    const t = incidentsSetup();
    const open = await driveTo(t, 'investigating');
    await expect(t.svc.addEvidence(open.id, { type: 'note', summary: 'other analyst' }, APPROVER)).rejects.toMatchObject({ code: 'NOT_INCIDENT_OWNER' });
    const closed = await driveTo(t, 'closed');
    await expect(t.svc.addEvidence(closed.id, { type: 'note', summary: 'too late' }, DEV)).rejects.toMatchObject({ code: 'INCIDENT_CLOSED' });
  });
  it('openFromEvent dedupes against an open incident and attaches evidence', async () => {
    const t = incidentsSetup();
    const ev = { id: 'e1', severity: 'high', category: 'authentication', occurredAt: now() };
    const a = await t.svc.openFromEvent({ event: ev, title: 'authentication: repeated ssh failures' });
    const b = await t.svc.openFromEvent({ event: { ...ev, id: 'e2' }, title: 'authentication: repeated ssh failures' });
    expect(b.id).toBe(a.id);
    expect(t.incs.size).toBe(1);
    expect((await t.svc.verifyEvidence(a.id, OWNER)).count).toBe(2);
  });
});

describe('security: Wazuh ingestion', () => {
  const alert = (id, level, groups, extra = {}) => ({ id, timestamp: '2026-06-01T00:00:00Z', rule: { level, description: `rule ${id}`, groups }, agent: { name: 'vps-app-01' }, ...extra });
  function secSetup(alerts) {
    const events = [];
    const prisma = {
      securityEvent: {
        findFirst: vi.fn(async ({ where }) => events.find((e) => e.payloadJson.wazuhId === where.payloadJson.equals) ?? null),
        create: vi.fn(async ({ data }) => { const e = { id: U(300 + events.length), ...data }; events.push(e); return e; }),
        findMany: vi.fn(async () => events),
      },
      server: { findFirst: vi.fn(async ({ where }) => (where.alias === 'vps-app-01' ? { id: U(5) } : null)) },
    };
    const adapters = createSimulatedAdapters();
    adapters.wazuh.fetchAlerts = vi.fn(async () => alerts);
    const incidents = { openFromEvent: vi.fn(async () => ({})) };
    const auditService = { record: vi.fn() };
    const rbac = makeRbac([{ userId: DEV.id, permissionKey: 'security.incident.manage', resourceId: 'platform', environmentId: null }]);
    return { events, prisma, adapters, incidents, auditService, svc: createSecurityService({ prisma, now, adapters, incidents, auditService, rbac }) };
  }
  it('maps level to severity and groups to categories', () => {
    expect([3, 6, 9, 12, 15].map(severityFromLevel)).toEqual(['low', 'medium', 'high', 'critical', 'critical']);
    expect(normalizeAlert(alert('a', 5, ['syscheck'])).category).toBe('fim');
    expect(normalizeAlert(alert('a', 5, ['sshd', 'authentication_failed'])).category).toBe('authentication');
    expect(normalizeAlert(alert('a', 5, ['sudo'])).category).toBe('sudo');
    expect(normalizeAlert(alert('a', 5, ['weird'])).category).toBe('other');
  });
  it('ingests scoped fixtures, dedupes, redacts secrets and opens incidents for high severity only', async () => {
    const t = secSetup([alert('1', 12, ['rootcheck'], { data: { password: 'p', srcip: '1.2.3.4' } }), alert('2', 3, ['sshd']), alert('1', 12, ['rootcheck'])]);
    const r = await t.svc.sync({ sinceMinutes: 60 }, DEV);
    expect(r).toMatchObject({ status: 'ok', ingested: 2, duplicates: 1, incidentsTouched: 1 });
    expect(t.events[0].serverId).toBe(U(5));
    expect(t.events[0].payloadJson.data.password).toBe('[REDACTED]');
    expect(t.events[0].payloadJson.independent).toBe(true);
    expect(r.notice).toMatch(/does not guarantee/);
  });
  it('flags unmapped agents and skips malformed alerts', async () => {
    const t = secSetup([{ ...alert('9', 7, ['ports']), agent: { name: 'rogue' } }, { id: 'bad', timestamp: 'nope' }, { rule: {} }]);
    const r = await t.svc.sync({ sinceMinutes: 5 }, DEV);
    expect(r.ingested).toBe(1);
    expect(t.events[0].serverId).toBeNull();
    expect(t.events[0].payloadJson.unmappedAgent).toBe(true);
  });
  it('degrades gracefully when Wazuh is unavailable and denies unauthorized sync', async () => {
    const t = secSetup([]);
    t.adapters.wazuh.fetchAlerts = vi.fn(async () => { throw new Error('ECONNREFUSED'); });
    expect(await t.svc.sync({ sinceMinutes: 5 }, DEV)).toMatchObject({ status: 'source_unavailable', ingested: 0 });
    t.adapters.wazuh.health = vi.fn(async () => { throw new Error('down'); });
    expect(await t.svc.connection()).toMatchObject({ connected: false, reason: 'source_unavailable' });
    await expect(t.svc.sync({ sinceMinutes: 5 }, { id: U(9), isOwner: false })).rejects.toMatchObject({ status: 403 });
  });
  it('summarises the last 24h with the coverage notice', async () => {
    const t = secSetup([alert('1', 12, ['rootcheck']), alert('2', 3, ['sshd'])]);
    await t.svc.sync({ sinceMinutes: 60 }, DEV);
    const s = await t.svc.summary(OWNER);
    expect(s.bySeverity.critical).toBe(1);
    expect(s.notice).toMatch(/indicators only/);
  });
});
