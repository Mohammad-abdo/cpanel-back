import { describe, expect, it, vi } from 'vitest';
import { createUsersService } from '../src/modules/users/users.service.js';

describe('users.service Owner protection', () => {
  it('denies non-Owner creating an Owner', async () => {
    const prisma = { user: { findUnique: vi.fn(), create: vi.fn() } };
    const users = createUsersService({ prisma });
    await expect(
      users.create(
        { email: 'x@example.com', displayName: 'X', password: 'password1', isOwner: true },
        { id: 'u2', isOwner: false },
      ),
    ).rejects.toMatchObject({ code: 'OWNER_ESCALATION_DENIED' });
  });

  it('denies non-Owner creating any user in this slice', async () => {
    const prisma = { user: { findUnique: vi.fn(), create: vi.fn() } };
    const users = createUsersService({ prisma });
    await expect(
      users.create(
        { email: 'x@example.com', displayName: 'X', password: 'password1', isOwner: false },
        { id: 'u2', isOwner: false },
      ),
    ).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });

  it('allows Owner to create a non-Owner user', async () => {
    const prisma = {
      user: {
        findUnique: vi.fn().mockResolvedValue(null),
        create: vi.fn().mockResolvedValue({
          id: 'u3',
          email: 'dev@example.com',
          displayName: 'Dev',
          ownerFlag: false,
          status: 'active',
          createdAt: new Date(),
        }),
      },
    };
    const users = createUsersService({ prisma });
    const row = await users.create(
      { email: 'dev@example.com', displayName: 'Dev', password: 'password1', isOwner: false },
      { id: 'owner', isOwner: true },
    );
    expect(row.email).toBe('dev@example.com');
    expect(row.isOwner).toBe(false);
  });

  it('blocks Owner self-demotion', async () => {
    const prisma = {
      user: {
        findUnique: vi.fn().mockResolvedValue({ id: 'owner', ownerFlag: true }),
        update: vi.fn(),
      },
    };
    const users = createUsersService({ prisma });
    await expect(
      users.patch('owner', { isOwner: false }, { id: 'owner', isOwner: true }),
    ).rejects.toMatchObject({ code: 'OWNER_LOCK' });
  });
});
