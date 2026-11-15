import { describe, expect, it, vi } from 'vitest';
import { createRbacService } from '../src/modules/rbac/rbac.service.js';
import { createTeamsService } from '../src/modules/teams/teams.service.js';
import { hashPassword, verifyPassword } from '../src/common/crypto/password.js';
import { createHash } from 'node:crypto';

const U = (n) => `00000000-0000-4000-8000-00000000000${n}`;
const ENV_STAGING = U(8);
const ENV_PROD = U(9);

describe('password hashing', () => {
  it('verifies scrypt hashes, rejects wrong passwords, salts uniquely', () => {
    const a = hashPassword('correct horse');
    expect(verifyPassword('correct horse', a)).toBe(true);
    expect(verifyPassword('wrong', a)).toBe(false);
    expect(hashPassword('correct horse')).not.toBe(a);
  });

  it('still verifies legacy sha256 hashes', () => {
    const legacy = createHash('sha256').update('pw').digest('hex');
    expect(verifyPassword('pw', legacy)).toBe(true);
    expect(verifyPassword('nope', legacy)).toBe(false);
  });
});

describe('rbac scope enforcement', () => {
  const input = {
    userId: U(2),
    permissionKey: 'project.deploy.create',
    resourceType: 'project',
    resourceId: 'p1',
    environmentId: ENV_PROD,
  };

  it('denies a non-owner who lacks the permission (scope expansion)', async () => {
    const prisma = { resourceGrant: { findFirst: vi.fn().mockResolvedValue(null), create: vi.fn() } };
    const rbac = createRbacService({ prisma });
    await expect(rbac.grant(input, { id: U(1), isOwner: false })).rejects.toMatchObject({
      code: 'SCOPE_EXPANSION_DENIED',
    });
    expect(prisma.resourceGrant.create).not.toHaveBeenCalled();
  });

  it('denies self-grant', async () => {
    const prisma = { resourceGrant: { findFirst: vi.fn(), create: vi.fn() } };
    const rbac = createRbacService({ prisma });
    await expect(rbac.grant({ ...input, userId: U(1) }, { id: U(1), isOwner: false })).rejects.toMatchObject({
      code: 'SELF_GRANT_DENIED',
    });
  });

  it('requires environment for project permissions', async () => {
    const prisma = { resourceGrant: { findFirst: vi.fn(), create: vi.fn() } };
    const rbac = createRbacService({ prisma });
    await expect(
      rbac.grant({ ...input, environmentId: null }, { id: U(1), isOwner: true }),
    ).rejects.toMatchObject({ code: 'ENVIRONMENT_REQUIRED' });
  });

  it('lets a delegate re-grant only what they hold and may assign', async () => {
    const prisma = {
      resourceGrant: { findFirst: vi.fn().mockResolvedValue({ id: 'g' }), create: vi.fn().mockResolvedValue({ id: 'new' }) },
    };
    const rbac = createRbacService({ prisma });
    await expect(rbac.grant(input, { id: U(1), isOwner: false })).resolves.toEqual({ id: 'new' });
  });

  it('hasGrant scopes the query to the exact environment and never matches env-less lookups', async () => {
    const findFirst = vi.fn().mockResolvedValue(null);
    const rbac = createRbacService({ prisma: { resourceGrant: { findFirst } } });
    expect(await rbac.hasGrant({ userId: U(1), permissionKey: 'project.deploy.create', resourceType: 'project', resourceId: 'p1' })).toBe(false);
    expect(findFirst).not.toHaveBeenCalled();
    await rbac.hasGrant({ userId: U(1), permissionKey: 'project.deploy.create', resourceType: 'project', resourceId: 'p1', environmentId: ENV_STAGING });
    expect(JSON.stringify(findFirst.mock.calls[0][0])).toContain(ENV_STAGING);
    expect(JSON.stringify(findFirst.mock.calls[0][0])).not.toContain(ENV_PROD);
  });

  it('only owner or original grantor may revoke', async () => {
    const prisma = {
      resourceGrant: {
        findUnique: vi.fn().mockResolvedValue({ id: 'g', grantedById: U(3), revokedAt: null }),
        update: vi.fn().mockResolvedValue({ id: 'g' }),
      },
    };
    const rbac = createRbacService({ prisma });
    await expect(rbac.revoke('g', { id: U(1), isOwner: false })).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await expect(rbac.revoke('g', { id: U(1), isOwner: true })).resolves.toEqual({ id: 'g' });
  });
});

describe('teams service', () => {
  const mk = (role) => ({
    team: { findUnique: vi.fn().mockResolvedValue({ id: 't' }), create: vi.fn() },
    user: { findUnique: vi.fn().mockResolvedValue({ id: U(2), status: 'active', disabledAt: null }) },
    teamMember: {
      findUnique: vi.fn().mockResolvedValue(role ? { teamRole: role } : null),
      upsert: vi.fn().mockResolvedValue({ ok: true }),
      delete: vi.fn(),
    },
  });

  it('only Owner creates teams', async () => {
    const teams = createTeamsService({ prisma: mk('lead') });
    await expect(teams.create({ name: 'Ops', slug: 'ops' }, { id: U(1), isOwner: false })).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });

  it('non-members cannot manage a team', async () => {
    const teams = createTeamsService({ prisma: mk(null) });
    await expect(teams.addMember(U(5), { userId: U(2), teamRole: 'developer' }, { id: U(1), isOwner: false })).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });

  it('team lead cannot appoint another lead', async () => {
    const teams = createTeamsService({ prisma: mk('lead') });
    await expect(teams.addMember(U(5), { userId: U(2), teamRole: 'lead' }, { id: U(1), isOwner: false })).rejects.toMatchObject({ code: 'SCOPE_EXPANSION_DENIED' });
  });

  it('team lead can add a developer', async () => {
    const teams = createTeamsService({ prisma: mk('lead') });
    await expect(teams.addMember(U(5), { userId: U(2), teamRole: 'developer' }, { id: U(1), isOwner: false })).resolves.toEqual({ ok: true });
  });

  it('team lead cannot remove a lead', async () => {
    const prisma = mk('lead');
    const teams = createTeamsService({ prisma });
    await expect(teams.removeMember(U(5), U(2), { id: U(1), isOwner: false })).rejects.toMatchObject({ code: 'SCOPE_EXPANSION_DENIED' });
    expect(prisma.teamMember.delete).not.toHaveBeenCalled();
  });
});
