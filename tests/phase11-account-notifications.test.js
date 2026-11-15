import { describe, expect, it, vi } from 'vitest';
import {
  createNotificationsService,
  notify,
  notifyOwners,
  redactText,
} from '../src/modules/notifications/notifications.service.js';
import {
  listNotificationsQuerySchema,
  updatePreferencesBodySchema,
} from '../src/modules/notifications/notifications.validator.js';

const U1 = '11111111-1111-4111-8111-111111111111';
const N1 = '22222222-2222-4222-8222-222222222222';

function makePrisma(over = {}) {
  return {
    notification: {
      findMany: vi.fn().mockResolvedValue([]),
      count: vi.fn().mockResolvedValue(0),
      updateMany: vi.fn().mockResolvedValue({ count: 1 }),
      findFirst: vi.fn().mockResolvedValue(null),
      create: vi.fn().mockImplementation(async ({ data }) => ({ id: 'n', ...data })),
    },
    notificationPreference: {
      findMany: vi.fn().mockResolvedValue([]),
      findUnique: vi.fn().mockResolvedValue(null),
      upsert: vi.fn().mockResolvedValue({}),
    },
    user: { findMany: vi.fn().mockResolvedValue([{ id: 'o1' }, { id: 'o2' }]) },
    ...over,
  };
}

describe('notifications scoping', () => {
  it('lists only the caller own notifications and the unread filter', async () => {
    const prisma = makePrisma();
    const svc = createNotificationsService({ prisma });
    await svc.list({ id: U1 }, { limit: 20, unread: 'true' });
    expect(prisma.notification.findMany.mock.calls[0][0].where).toEqual({ userId: U1, readAt: null });
    expect(prisma.notification.count.mock.calls[0][0].where).toEqual({ userId: U1, readAt: null });
  });

  it('marking read is scoped to the user and 404s for someone else notification', async () => {
    const prisma = makePrisma();
    prisma.notification.updateMany.mockResolvedValue({ count: 0 });
    const svc = createNotificationsService({ prisma });
    await expect(svc.markRead({ id: U1 }, N1)).rejects.toMatchObject({ status: 404 });
    expect(prisma.notification.updateMany.mock.calls[0][0].where).toMatchObject({ id: N1, userId: U1 });
  });

  it('read-all only touches the caller rows', async () => {
    const prisma = makePrisma();
    const svc = createNotificationsService({ prisma });
    await svc.markAllRead({ id: U1 });
    expect(prisma.notification.updateMany.mock.calls[0][0].where).toEqual({ userId: U1, readAt: null });
  });

  it('paginates with a next cursor', async () => {
    const prisma = makePrisma();
    prisma.notification.findMany.mockResolvedValue([{ id: 'a' }, { id: 'b' }, { id: 'c' }]);
    const svc = createNotificationsService({ prisma });
    const res = await svc.list({ id: U1 }, { limit: 2 });
    expect(res.items).toHaveLength(2);
    expect(res.nextCursor).toBe('b');
  });
});

describe('notification preferences', () => {
  it('returns a full matrix defaulting to enabled', async () => {
    const svc = createNotificationsService({ prisma: makePrisma() });
    const prefs = await svc.getPreferences({ id: U1 });
    expect(prefs.length).toBe(8);
    expect(prefs.every((p) => p.enabled)).toBe(true);
  });

  it('validator rejects unknown kinds, extra keys and empty lists', () => {
    const ok = { preferences: [{ eventKind: 'alert.opened', channelType: 'in_app', enabled: false }] };
    expect(updatePreferencesBodySchema.safeParse(ok).success).toBe(true);
    expect(updatePreferencesBodySchema.safeParse({ preferences: [] }).success).toBe(false);
    expect(
      updatePreferencesBodySchema.safeParse({ preferences: [{ eventKind: 'nope', channelType: 'in_app', enabled: true }] }).success,
    ).toBe(false);
    expect(
      updatePreferencesBodySchema.safeParse({ preferences: [{ ...ok.preferences[0], userId: U1 }] }).success,
    ).toBe(false);
    expect(updatePreferencesBodySchema.safeParse({ ...ok, extra: 1 }).success).toBe(false);
  });

  it('list query is strict', () => {
    expect(listNotificationsQuerySchema.safeParse({ unread: 'true', userId: U1 }).success).toBe(false);
    expect(listNotificationsQuerySchema.safeParse({ limit: '500' }).success).toBe(false);
  });

  it('upserts only for the caller', async () => {
    const prisma = makePrisma();
    const svc = createNotificationsService({ prisma });
    await svc.updatePreferences(
      { id: U1 },
      { preferences: [{ eventKind: 'alert.opened', channelType: 'in_app', enabled: false }] },
    );
    expect(prisma.notificationPreference.upsert.mock.calls[0][0].create.userId).toBe(U1);
  });
});

describe('notify helper', () => {
  it('redacts secrets and never throws', async () => {
    expect(redactText('deploy failed password=hunter2 token: abc123')).not.toMatch(/hunter2|abc123/);
    const prisma = makePrisma();
    const row = await notify({ userId: U1, type: 'alert.opened', title: 'x', body: 'secret=zzz' }, { prisma });
    expect(row.body).not.toContain('zzz');
    prisma.notification.create.mockRejectedValue(new Error('db down'));
    await expect(notify({ userId: U1, type: 'alert.opened', title: 'x' }, { prisma })).resolves.toBeNull();
  });

  it('skips when the user disabled in_app for that kind', async () => {
    const prisma = makePrisma();
    prisma.notificationPreference.findUnique.mockResolvedValue({ enabled: false });
    expect(await notify({ userId: U1, type: 'alert.opened', title: 'x' }, { prisma })).toBeNull();
    expect(prisma.notification.create).not.toHaveBeenCalled();
  });

  it('notifyOwners skips the actor and tolerates a mock without user model', async () => {
    const prisma = makePrisma();
    await notifyOwners({ type: 'approval.requested', title: 't' }, { prisma, exceptUserId: 'o1' });
    expect(prisma.notification.create).toHaveBeenCalledTimes(1);
    await expect(notifyOwners({ type: 'x', title: 't' }, { prisma: {} })).resolves.toBeUndefined();
  });
});
