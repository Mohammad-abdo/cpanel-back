import { describe, expect, it, vi } from 'vitest';
import { randomUUID, createHmac } from 'node:crypto';
import { createAlertChannelsService, MAX_ATTEMPTS, backoffMs } from '../src/modules/alert-channels/alert-channels.service.js';
import { assertSafeUrl, isPrivateAddress, safeFetch } from '../src/modules/alert-channels/alert-channels.ssrf.js';
import { signPayload, sanitizeError } from '../src/modules/alert-channels/alert-channels.senders.js';
import { createChannelBodySchema, updateChannelBodySchema } from '../src/modules/alert-channels/alert-channels.validator.js';
import { dispatchAlertChannels } from '../src/modules/alert-channels/alert-channels.dispatch.js';
import { makeRbac } from './phase6-helpers.js';

const KEY = 'c'.repeat(64);
const OWNER = { id: randomUUID(), isOwner: true };
const DEV = { id: randomUUID(), isOwner: false };
const PUBLIC_LOOKUP = async () => [{ address: '93.184.216.34', family: 4 }];
const PRIVATE_LOOKUP = async () => [{ address: '10.0.0.5', family: 4 }];
const TG_TOKEN = '123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const SLACK = 'https://hooks.slack.com/services/T000/B000/SECRETSECRETSECRET';

function fakePrisma(clock) {
  const channels = new Map();
  const deliveries = new Map();
  const match = (row, where = {}) =>
    Object.entries(where).every(([k, v]) => {
      if (v && typeof v === 'object' && !(v instanceof Date)) {
        if ('in' in v) return v.in.includes(row[k]);
        if ('not' in v) return row[k] !== v.not;
        if ('gte' in v) return row[k] >= v.gte;
        if ('lte' in v) return row[k] != null && row[k] <= v.lte;
        return true;
      }
      return row[k] === v;
    });
  return {
    channels,
    deliveries,
    alertChannel: {
      create: vi.fn(async ({ data }) => {
        const row = { id: randomUUID(), createdAt: new Date(), updatedAt: new Date(), archivedAt: null, lastTestAt: null, lastTestStatus: null, ...data };
        channels.set(row.id, row);
        return row;
      }),
      findUnique: vi.fn(async ({ where }) => channels.get(where.id) ?? null),
      findMany: vi.fn(async ({ where }) => [...channels.values()].filter((r) => match(r, where))),
      update: vi.fn(async ({ where, data }) => Object.assign(channels.get(where.id), data)),
    },
    alertChannelDelivery: {
      create: vi.fn(async ({ data }) => {
        const row = { id: randomUUID(), createdAt: new Date(clock.t), attempt: 0, nextAttemptAt: null, sentAt: null, error: null, ...data };
        deliveries.set(row.id, row);
        return row;
      }),
      update: vi.fn(async ({ where, data }) => Object.assign(deliveries.get(where.id), data)),
      findFirst: vi.fn(async ({ where }) => [...deliveries.values()].find((r) => match(r, where)) ?? null),
      count: vi.fn(async ({ where }) => [...deliveries.values()].filter((r) => match(r, where)).length),
      findMany: vi.fn(async ({ where, take }) => [...deliveries.values()].filter((r) => match(r, where)).slice(0, take)),
    },
  };
}

const okRes = (status = 200) => ({ status, body: null });

function setup({ grants = [], fetchImpl = vi.fn(async () => okRes()), lookup = PUBLIC_LOOKUP, clock = { t: Date.parse('2026-11-17T10:00:00Z') } } = {}) {
  const prisma = fakePrisma(clock);
  const auditService = { record: vi.fn(async () => ({})) };
  const svc = createAlertChannelsService({ prisma, rbac: makeRbac(grants), auditService, credentialKey: () => KEY, fetchImpl, lookup, now: () => new Date(clock.t) });
  return { prisma, auditService, svc, fetchImpl, clock };
}
const slackInput = (extra = {}) => ({ type: 'slack', name: 'Ops', webhookUrl: SLACK, ...extra });

describe('SSRF guard', () => {
  it.each(['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', 'fc00::1', 'fe80::1', '::ffff:127.0.0.1', '::ffff:7f00:1'])('treats %s as private', (ip) => {
    expect(isPrivateAddress(ip)).toBe(true);
  });
  it('treats public addresses as public', () => {
    expect(isPrivateAddress('93.184.216.34')).toBe(false);
    expect(isPrivateAddress('2606:4700:4700::1111')).toBe(false);
  });
  it('blocks http, credentials, localhost, IP literals and private DNS results', async () => {
    await expect(assertSafeUrl('http://example.com/x', { lookup: PUBLIC_LOOKUP })).rejects.toMatchObject({ code: 'URL_NOT_HTTPS' });
    await expect(assertSafeUrl('https://user:pw@example.com/', { lookup: PUBLIC_LOOKUP })).rejects.toMatchObject({ code: 'URL_CREDENTIALS' });
    await expect(assertSafeUrl('https://localhost/', { lookup: PUBLIC_LOOKUP })).rejects.toMatchObject({ code: 'URL_HOST_BLOCKED' });
    await expect(assertSafeUrl('https://169.254.169.254/latest', { lookup: PUBLIC_LOOKUP })).rejects.toMatchObject({ code: 'URL_PRIVATE_ADDRESS' });
    await expect(assertSafeUrl('https://[::1]/', { lookup: PUBLIC_LOOKUP })).rejects.toMatchObject({ code: 'URL_PRIVATE_ADDRESS' });
    await expect(assertSafeUrl('https://evil.example.com/', { lookup: PRIVATE_LOOKUP })).rejects.toMatchObject({ code: 'URL_PRIVATE_ADDRESS' });
    await expect(assertSafeUrl('https://evil.example.com/', { lookup: async () => [{ address: '93.184.216.34' }, { address: '127.0.0.1' }] })).rejects.toMatchObject({ code: 'URL_PRIVATE_ADDRESS' });
    await expect(assertSafeUrl('https://example.com/', { lookup: PUBLIC_LOOKUP, allowHosts: ['hooks.slack.com'] })).rejects.toMatchObject({ code: 'URL_HOST_NOT_ALLOWED' });
    await expect(assertSafeUrl('https://example.com/', { lookup: PUBLIC_LOOKUP })).resolves.toBeTruthy();
  });
  it('never follows redirects and does not call fetch for blocked hosts', async () => {
    const fetchImpl = vi.fn(async () => ({ status: 302, body: null }));
    await expect(safeFetch('https://example.com/', { fetchImpl, lookup: PUBLIC_LOOKUP })).rejects.toMatchObject({ code: 'REDIRECT_BLOCKED' });
    expect(fetchImpl.mock.calls[0][1].redirect).toBe('manual');
    const never = vi.fn();
    await expect(safeFetch('https://example.com/', { fetchImpl: never, lookup: PRIVATE_LOOKUP })).rejects.toMatchObject({ code: 'URL_PRIVATE_ADDRESS' });
    expect(never).not.toHaveBeenCalled();
  });
  it('caps the response size it reads', async () => {
    const cancel = vi.fn();
    const chunks = [new Uint8Array(40000), new Uint8Array(40000), new Uint8Array(40000)];
    const reader = { read: vi.fn(async () => (chunks.length ? { done: false, value: chunks.shift() } : { done: true })), cancel };
    const res = await safeFetch('https://example.com/', { fetchImpl: async () => ({ status: 200, body: { getReader: () => reader } }), lookup: PUBLIC_LOOKUP, maxBytes: 64 * 1024 });
    expect(res.ok).toBe(true);
    expect(cancel).toHaveBeenCalled();
  });
  it('blocks a webhook channel pointing at a private host on create', async () => {
    const { svc } = setup({ lookup: PRIVATE_LOOKUP });
    await expect(svc.create({ type: 'webhook', name: 'x', url: 'https://hook.example.com/in', signingSecret: 's'.repeat(20) }, OWNER)).rejects.toMatchObject({ code: 'URL_PRIVATE_ADDRESS' });
  });
});

describe('validators', () => {
  it('requires https and provider host allow-list', () => {
    expect(createChannelBodySchema.safeParse({ type: 'slack', name: 'a', webhookUrl: 'http://hooks.slack.com/x' }).success).toBe(false);
    expect(createChannelBodySchema.safeParse({ type: 'slack', name: 'a', webhookUrl: 'https://evil.example.com/x' }).success).toBe(false);
    expect(createChannelBodySchema.safeParse({ type: 'discord', name: 'a', webhookUrl: 'https://discord.com/api/webhooks/1/abc' }).success).toBe(true);
    expect(createChannelBodySchema.safeParse({ type: 'telegram', name: 'a', botToken: TG_TOKEN }).success).toBe(false);
    expect(createChannelBodySchema.safeParse({ type: 'telegram', name: 'a', botToken: TG_TOKEN, chatId: '-100123' }).success).toBe(true);
    expect(createChannelBodySchema.safeParse({ type: 'webhook', name: 'a', url: 'https://x.example.com/h', signingSecret: 'short' }).success).toBe(false);
    expect(createChannelBodySchema.safeParse({ ...slackInput(), extra: 1 }).success).toBe(false);
    expect(updateChannelBodySchema.safeParse({}).success).toBe(false);
  });
});

describe('secret handling', () => {
  it('encrypts the secret at rest and never returns it', async () => {
    const { svc, prisma, auditService } = setup();
    const created = await svc.create(slackInput(), OWNER);
    const row = prisma.channels.get(created.id);
    expect(Buffer.isBuffer(row.secretEnc)).toBe(true);
    expect(row.secretEnc.toString('utf8')).not.toContain('SECRETSECRET');
    expect(JSON.stringify(created)).not.toContain('SECRETSECRET');
    expect(created).toMatchObject({ secretSet: true, secretMasked: '********', config: { host: 'hooks.slack.com' } });
    expect(JSON.stringify(await svc.list(OWNER))).not.toContain('SECRETSECRET');
    expect(JSON.stringify(await svc.get(created.id, OWNER))).not.toContain('SECRETSECRET');
    expect(JSON.stringify(auditService.record.mock.calls)).not.toContain('SECRETSECRET');
  });
  it('keeps the secret when omitted on update and replaces it when provided', async () => {
    const { svc, prisma } = setup();
    const c = await svc.create(slackInput(), OWNER);
    const before = prisma.channels.get(c.id).secretEnc;
    await svc.update(c.id, { name: 'Renamed', enabled: false }, OWNER);
    expect(prisma.channels.get(c.id).secretEnc).toBe(before);
    await svc.update(c.id, { webhookUrl: 'https://hooks.slack.com/services/T1/B1/NEWNEWNEW' }, OWNER);
    expect(prisma.channels.get(c.id).secretEnc).not.toBe(before);
    await expect(svc.update(c.id, { botToken: TG_TOKEN }, OWNER)).rejects.toMatchObject({ code: 'FIELD_NOT_FOR_TYPE' });
  });
  it('wipes the secret on delete and hides the channel', async () => {
    const { svc, prisma } = setup();
    const c = await svc.create(slackInput(), OWNER);
    await svc.remove(c.id, OWNER);
    expect(prisma.channels.get(c.id).secretEnc.length).toBe(0);
    await expect(svc.get(c.id, OWNER)).rejects.toMatchObject({ code: 'CHANNEL_NOT_FOUND' });
    expect(await svc.list(OWNER)).toEqual([]);
  });
  it('sanitizes error text (secrets, urls, bot tokens)', () => {
    const msg = sanitizeError(new Error(`connect failed https://api.telegram.org/bot${TG_TOKEN}/sendMessage token=abc ${TG_TOKEN}`), [TG_TOKEN]);
    expect(msg).not.toContain(TG_TOKEN);
    expect(msg).not.toContain('api.telegram.org');
  });
  it('stores a delivery error without leaking the secret when the network fails', async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error(`fetch failed for ${SLACK}`);
    });
    const { svc, prisma } = setup({ fetchImpl });
    await svc.create(slackInput(), OWNER);
    await svc.dispatch({ kind: 'alert.opened', severity: 'critical', title: 'Boom', resourceId: 'a1' });
    const d = [...prisma.deliveries.values()][0];
    expect(d.status).toBe('failed');
    expect(d.error).not.toContain('SECRETSECRET');
    expect(JSON.stringify(d)).not.toContain('SECRETSECRET');
  });
});

describe('signature and payload formats', () => {
  it('signs webhook payloads with HMAC-SHA256 over timestamp.body', async () => {
    const { svc, fetchImpl } = setup();
    const secret = 'whsec_' + 'a'.repeat(30);
    const c = await svc.create({ type: 'webhook', name: 'wh', url: 'https://hook.example.com/in', signingSecret: secret }, OWNER);
    await svc.test(c.id, OWNER);
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe('https://hook.example.com/in');
    const ts = init.headers['x-nodeteam-timestamp'];
    const expected = 'sha256=' + createHmac('sha256', secret).update(`${ts}.${init.body}`).digest('hex');
    expect(init.headers['x-nodeteam-signature']).toBe(expected);
    expect(signPayload(secret, ts, init.body)).toBe(expected);
    expect(JSON.parse(init.body)).toMatchObject({ event: 'test', severity: 'info' });
    expect(init.redirect).toBe('manual');
  });
  it('builds telegram, slack and discord requests', async () => {
    const { svc, fetchImpl } = setup();
    const tg = await svc.create({ type: 'telegram', name: 't', botToken: TG_TOKEN, chatId: '-1001' }, OWNER);
    const dc = await svc.create({ type: 'discord', name: 'd', webhookUrl: 'https://discord.com/api/webhooks/1/abc' }, OWNER);
    const sl = await svc.create(slackInput(), OWNER);
    for (const c of [tg, dc, sl]) expect((await svc.test(c.id, OWNER)).ok).toBe(true);
    const calls = fetchImpl.mock.calls.map(([u, i]) => [u, JSON.parse(i.body)]);
    expect(calls[0][0]).toBe(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`);
    expect(calls[0][1]).toMatchObject({ chat_id: '-1001' });
    expect(calls[1][1].content).toContain('test notification');
    expect(calls[2][1].text).toContain('test notification');
  });
  it('test-send reports failure without secrets and records lastTestStatus', async () => {
    const { svc, prisma } = setup({ fetchImpl: vi.fn(async () => okRes(404)) });
    const c = await svc.create(slackInput(), OWNER);
    const res = await svc.test(c.id, OWNER);
    expect(res).toMatchObject({ ok: false, status: 'dead', error: 'HTTP 404' });
    expect(prisma.channels.get(c.id).lastTestStatus).toBe('failed');
  });
});

describe('filters, dedupe and rate limit', () => {
  it('applies the per-channel severity filter and event kind filter', async () => {
    const { svc, fetchImpl } = setup();
    await svc.create(slackInput({ name: 'crit-only', minSeverity: 'critical' }), OWNER);
    await svc.create(slackInput({ name: 'backups', eventKinds: ['backup.failed'] }), OWNER);
    const r1 = await svc.dispatch({ kind: 'alert.opened', severity: 'warning', title: 'w', resourceId: '1' });
    expect(r1.matched).toBe(0);
    const r2 = await svc.dispatch({ kind: 'alert.opened', severity: 'critical', title: 'c', resourceId: '2' });
    expect(r2).toMatchObject({ matched: 1, sent: 1 });
    const r3 = await svc.dispatch({ kind: 'backup.failed', severity: 'warning', title: 'b', resourceId: '3' });
    expect(r3.matched).toBe(1);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });
  it('skips disabled channels', async () => {
    const { svc, fetchImpl } = setup();
    await svc.create(slackInput({ enabled: false }), OWNER);
    expect((await svc.dispatch({ kind: 'alert.opened', severity: 'critical', title: 'x', resourceId: '1' })).matched).toBe(0);
    expect(fetchImpl).not.toHaveBeenCalled();
  });
  it('deduplicates the same event within the window and logs it as suppressed', async () => {
    const { svc, prisma, fetchImpl, clock } = setup();
    await svc.create(slackInput({ dedupeSeconds: 300 }), OWNER);
    const ev = { kind: 'alert.opened', severity: 'critical', title: 'dup', resourceId: 'same' };
    await svc.dispatch(ev);
    const second = await svc.dispatch(ev);
    expect(second.suppressed).toBe(1);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect([...prisma.deliveries.values()].some((d) => d.status === 'suppressed' && d.error === 'deduplicated')).toBe(true);
    clock.t += 301_000;
    expect((await svc.dispatch(ev)).sent).toBe(1);
  });
  it('rate limits a channel per minute', async () => {
    const { svc, fetchImpl } = setup();
    await svc.create(slackInput({ dedupeSeconds: 0 }), OWNER);
    for (let i = 0; i < 25; i += 1) await svc.dispatch({ kind: 'alert.opened', severity: 'critical', title: `t${i}`, resourceId: `r${i}` });
    expect(fetchImpl.mock.calls.length).toBe(20);
  });
  it('redacts secret-looking text in the stored payload', async () => {
    const { svc, prisma } = setup();
    await svc.create(slackInput(), OWNER);
    await svc.dispatch({ kind: 'alert.opened', severity: 'critical', title: 'x', body: 'password=hunter2 failed', resourceId: '1' });
    const d = [...prisma.deliveries.values()][0];
    expect(JSON.stringify(d.payloadJson)).not.toContain('hunter2');
  });
  it('never throws from dispatch even when persistence fails', async () => {
    const { svc, prisma } = setup();
    prisma.alertChannel.findMany.mockRejectedValue(new Error('db down'));
    await expect(svc.dispatch({ kind: 'alert.opened', title: 'x' })).resolves.toMatchObject({ matched: 0 });
  });
});

describe('retry with backoff', () => {
  it('backs off exponentially and caps at one hour', () => {
    expect([1, 2, 3, 4].map(backoffMs)).toEqual([30000, 60000, 120000, 240000]);
    expect(backoffMs(20)).toBe(3_600_000);
  });
  it('retries failed deliveries when due, succeeds, and goes dead after max attempts', async () => {
    const fetchImpl = vi.fn(async () => okRes(503));
    const { svc, prisma, clock } = setup({ fetchImpl });
    await svc.create(slackInput(), OWNER);
    await svc.dispatch({ kind: 'alert.opened', severity: 'critical', title: 'r', resourceId: '1' });
    const d = [...prisma.deliveries.values()][0];
    expect(d).toMatchObject({ status: 'failed', attempt: 1 });
    expect((await svc.retryDue(new Date(clock.t))).retried).toBe(0); // not due yet
    for (let i = d.attempt; i < MAX_ATTEMPTS; i += 1) {
      clock.t = d.nextAttemptAt?.getTime() ?? clock.t;
      await svc.retryDue(new Date(clock.t + 1));
    }
    expect(d.status).toBe('dead');
    expect(d.attempt).toBe(MAX_ATTEMPTS);
    expect(d.nextAttemptAt).toBeNull();
  });
  it('recovers on a later attempt', async () => {
    const fetchImpl = vi.fn().mockResolvedValueOnce(okRes(500)).mockResolvedValue(okRes(200));
    const { svc, prisma, clock } = setup({ fetchImpl });
    await svc.create(slackInput(), OWNER);
    await svc.dispatch({ kind: 'alert.opened', severity: 'critical', title: 'r', resourceId: '1' });
    clock.t += 31_000;
    expect(await svc.retryDue(new Date(clock.t))).toMatchObject({ retried: 1, sent: 1 });
    expect([...prisma.deliveries.values()][0].status).toBe('sent');
  });
  it('does not retry permanent client errors or SSRF blocks', async () => {
    const { svc, prisma } = setup({ fetchImpl: vi.fn(async () => okRes(400)) });
    await svc.create(slackInput(), OWNER);
    await svc.dispatch({ kind: 'alert.opened', severity: 'critical', title: 'r', resourceId: '1' });
    expect([...prisma.deliveries.values()][0]).toMatchObject({ status: 'dead', attempt: 1 });
    const rebind = setup({ lookup: PUBLIC_LOOKUP });
    await rebind.svc.create(slackInput(), OWNER);
    const evil = createAlertChannelsService({ prisma: rebind.prisma, rbac: makeRbac(), credentialKey: () => KEY, fetchImpl: rebind.fetchImpl, lookup: PRIVATE_LOOKUP });
    await evil.dispatch({ kind: 'alert.opened', severity: 'critical', title: 'r', resourceId: '9' });
    expect([...rebind.prisma.deliveries.values()][0]).toMatchObject({ status: 'dead' });
    expect(rebind.fetchImpl).not.toHaveBeenCalled();
  });
});

describe('RBAC', () => {
  it('denies users without notifications.manage on every operation', async () => {
    const { svc } = setup();
    const c = await svc.create(slackInput(), OWNER);
    for (const fn of [() => svc.list(DEV), () => svc.get(c.id, DEV), () => svc.create(slackInput(), DEV), () => svc.update(c.id, { name: 'x' }, DEV), () => svc.remove(c.id, DEV), () => svc.test(c.id, DEV), () => svc.deliveries(c.id, {}, DEV)]) {
      await expect(fn()).rejects.toMatchObject({ status: 403 });
    }
    await expect(svc.list({})).rejects.toMatchObject({ status: 401 });
  });
  it('allows a user holding notifications.manage, and audits mutations', async () => {
    const { svc, auditService } = setup({ grants: [{ userId: DEV.id, permissionKey: 'notifications.manage', resourceId: 'global', environmentId: null }] });
    const c = await svc.create(slackInput(), DEV);
    await svc.update(c.id, { enabled: false }, DEV);
    await svc.test(c.id, DEV);
    await svc.remove(c.id, DEV);
    expect(auditService.record.mock.calls.map(([e]) => e.action)).toEqual(['alert_channel.create', 'alert_channel.update', 'alert_channel.test', 'alert_channel.delete']);
  });
});

describe('stale Prisma client and hook', () => {
  it('answers 501 SCHEMA_REQUIRED when the client predates the models', async () => {
    const svc = createAlertChannelsService({ prisma: {}, credentialKey: () => KEY });
    await expect(svc.list(OWNER)).rejects.toMatchObject({ status: 501, code: 'SCHEMA_REQUIRED' });
  });
  it('dispatchAlertChannels ignores unknown kinds, tolerates stale clients and forwards known events', async () => {
    expect(dispatchAlertChannels({ type: 'unknown.kind', title: 'x' }, { prisma: {} })).toBeNull();
    expect(dispatchAlertChannels({ type: 'alert.opened', title: 'x' }, { prisma: {} })).toBeNull();
    const service = { dispatch: vi.fn(async () => ({})) };
    await dispatchAlertChannels({ type: 'backup.failed', severity: 'critical', title: 'b', resourceId: 'p' }, { prisma: { alertChannel: { findMany() {} } }, service });
    expect(service.dispatch).toHaveBeenCalledWith(expect.objectContaining({ kind: 'backup.failed', severity: 'critical' }));
  });
});
