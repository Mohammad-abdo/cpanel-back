/**
 * Dev/isolated seed for Laragon MySQL. Requires DATABASE_URL from apps/api/.env.
 * Change the Owner password after first login.
 */
import { PrismaClient } from '@prisma/client';
import { PERMISSION_LIST, PERMISSION_RISK, permissionResourceType } from '../src/common/permission-catalog.js';
import { ROLE_DEFINITIONS } from '../src/modules/rbac/rbac.roles.js';
import { hashPassword } from '../src/common/crypto/password.js';

const prisma = new PrismaClient();

export async function seedRoles(db) {
  const perms = {};
  for (const code of PERMISSION_LIST) {
    perms[code] = await db.permission.upsert({
      where: { code },
      update: { riskTier: PERMISSION_RISK[code] ?? 'high', resourceType: permissionResourceType(code) },
      create: { code, riskTier: PERMISSION_RISK[code] ?? 'high', resourceType: permissionResourceType(code) },
    });
  }
  for (const [code, def] of Object.entries(ROLE_DEFINITIONS)) {
    const role = await db.role.upsert({ where: { code }, update: { name: def.name }, create: { code, name: def.name, systemProtected: true } });
    for (const key of def.permissions) {
      await db.rolePermission.upsert({
        where: { roleId_permissionId: { roleId: role.id, permissionId: perms[key].id } },
        update: {},
        create: { roleId: role.id, permissionId: perms[key].id },
      });
    }
  }
}

async function main() {
  await seedRoles(prisma);
  const email = (process.env.SEED_OWNER_EMAIL || 'owner@localhost.local').toLowerCase();
  const password = process.env.SEED_OWNER_PASSWORD || 'change-me-now-please';
  const displayName = process.env.SEED_OWNER_NAME || 'Owner';

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    console.info(`Owner already present: ${email}`);
    return;
  }

  await prisma.user.create({
    data: {
      email,
      displayName,
      passwordHash: hashPassword(password),
      ownerFlag: true,
      status: 'active',
    },
  });
  console.info(`Seeded Owner ${email} (change password immediately)`);
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
