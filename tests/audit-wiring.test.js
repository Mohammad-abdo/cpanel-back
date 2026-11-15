import { describe, expect, it, vi } from 'vitest';
import { createAuditService, redact } from '../src/modules/audit/audit.service.js';
import { createRbacService } from '../src/modules/rbac/rbac.service.js';
import { createTeamsService } from '../src/modules/teams/teams.service.js';

const U = '00000000-0000-4000-8000-000000000001';

describe('audit service', () => {
  it('redacts secret-looking keys recursively', () => {
    expect(redact({ a: 1, password: 'x', nested: { apiKey: 'k', ok: true }, list: [{ token: 't' }] })).toEqual({
      a: 1,
      password: '[REDACTED]',
      nested: { apiKey: '[REDACTED]', ok: true },
      list: [{ token: '[REDACTED]' }],
    });
  });

  it('defaults occurredAt and stores redacted payloads', async () => {
    const create = vi.fn().mockResolvedValue({});
    const fixed = new Date('2026-11-15T10:00:00Z');
    await createAuditService({ prisma: { auditEvent: { create } }, now: () => fixed }).record({
      actorId: U,
      action: 'x',
      resourceType: 'r',
      result: 'success',
      after: { secret: 's' },
    });
    const data = create.mock.calls[0][0].data;
    expect(data.occurredAt).toEqual(fixed);
    expect(data.afterJson).toEqual({ secret: '[REDACTED]' });
  });
});

describe('audit wiring', () => {
  it('records a denied grant attempt', async () => {
    const record = vi.fn();
    const prisma = { resourceGrant: { findFirst: vi.fn().mockResolvedValue(null) } };
    const rbac = createRbacService({ prisma, auditService: { record } });
    await expect(
      rbac.grant(
        { userId: '00000000-0000-4000-8000-000000000002', permissionKey: 'server.metrics.read', resourceType: 'server', resourceId: 's1' },
        { id: U, isOwner: false },
      ),
    ).rejects.toMatchObject({ code: 'SCOPE_EXPANSION_DENIED' });
    expect(record).toHaveBeenCalledWith(expect.objectContaining({ action: 'rbac.grant', result: 'denied' }));
  });

  it('records team creation by Owner', async () => {
    const record = vi.fn();
    const prisma = { team: { findUnique: vi.fn().mockResolvedValue(null), create: vi.fn().mockResolvedValue({ id: 't1' }) } };
    await createTeamsService({ prisma, auditService: { record } }).create({ name: 'Ops', slug: 'ops' }, { id: U, isOwner: true });
    expect(record).toHaveBeenCalledWith(expect.objectContaining({ action: 'team.create', resourceId: 't1' }));
  });
});
