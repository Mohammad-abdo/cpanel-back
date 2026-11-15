import { describe, expect, it } from 'vitest';
import { createRbacService } from '../src/modules/rbac/rbac.service.js';
import { ROLE_DEFINITIONS, isRoleAssignableTo, roleHasPermission } from '../src/modules/rbac/rbac.roles.js';
import { PERMISSION_LIST, PERMISSION_RISK } from '../src/common/permission-catalog.js';

const roleRow = (code, scopeType = '', scopeId = '') => ({
  scopeType,
  scopeId,
  role: { code, rolePermissions: ROLE_DEFINITIONS[code].permissions.map((p) => ({ permission: { code: p } })) },
});
const svc = (userRoles = []) =>
  createRbacService({
    prisma: { resourceGrant: { findFirst: async () => null }, userRole: { findMany: async () => userRoles } },
  });
const user = { id: 'u1' };

describe('role catalog', () => {
  it('defines 8 roles and every permission has a risk tier', () => {
    expect(Object.keys(ROLE_DEFINITIONS)).toHaveLength(8);
    for (const k of PERMISSION_LIST) expect(PERMISSION_RISK[k]).toBeTruthy();
    expect(PERMISSION_RISK['platform.approval.decide']).toBe('high');
    expect(PERMISSION_RISK['project.configure']).toBe('medium');
  });
  it('only Owner holds Owner role; only Team Lead holds team.permission.assign besides Owner', () => {
    expect(isRoleAssignableTo('owner', { isOwner: false })).toBe(false);
    expect(isRoleAssignableTo('developer', { isOwner: false })).toBe(true);
    const holders = Object.keys(ROLE_DEFINITIONS).filter((r) => roleHasPermission(r, 'team.permission.assign'));
    expect(holders.sort()).toEqual(['owner', 'team_lead']);
  });
  it('auditor is read-only', () => {
    for (const p of ROLE_DEFINITIONS.auditor.permissions) expect(p).toMatch(/\.(read|export)$/);
  });
});

describe('rbac.can with roles', () => {
  it('owner bypasses', async () => {
    expect(await svc().can({ id: 'o', isOwner: true }, { permissionKey: 'ssl.issue', resourceType: 'project', resourceId: 'p' })).toBe(true);
  });
  it('denies with no grant or role', async () => {
    expect(await svc().can(user, { permissionKey: 'platform.access.review', resourceType: 'platform', resourceId: 'platform' })).toBe(false);
  });
  it('global role grants non-environment permission', async () => {
    const s = svc([roleRow('security_analyst')]);
    expect(await s.can(user, { permissionKey: 'security.incident.manage', resourceType: 'platform', resourceId: 'platform' })).toBe(true);
    expect(await s.can(user, { permissionKey: 'platform.approval.decide', resourceType: 'platform', resourceId: 'platform' })).toBe(false);
  });
  it('staging role never implies production', async () => {
    const s = svc([roleRow('devops', 'environment', 'staging')]);
    const c = { permissionKey: 'project.deploy.create', resourceType: 'project', resourceId: 'p' };
    expect(await s.can(user, { ...c, environmentId: 'staging' })).toBe(true);
    expect(await s.can(user, { ...c, environmentId: 'prod' })).toBe(false);
    expect(await s.can(user, c)).toBe(false);
  });
  it('global role does not satisfy environment-scoped permission', async () => {
    const s = svc([roleRow('devops')]);
    expect(await s.can(user, { permissionKey: 'project.deploy.create', resourceType: 'project', resourceId: 'p', environmentId: 'prod' })).toBe(false);
  });
  it('developer lacks deploy and restore without explicit grant', async () => {
    const s = svc([roleRow('developer', 'environment', 'staging')]);
    for (const k of ['project.deploy.create', 'project.backup.restore', 'project.secret.rotate'])
      expect(await s.can(user, { permissionKey: k, resourceType: 'project', resourceId: 'p', environmentId: 'staging' })).toBe(false);
  });
  it('team lead assign only within own team', async () => {
    const s = svc([roleRow('team_lead', 'team', 't1')]);
    const c = { permissionKey: 'team.permission.assign', resourceType: 'team' };
    expect(await s.can(user, { ...c, resourceId: 't1' })).toBe(true);
    expect(await s.can(user, { ...c, resourceId: 't2' })).toBe(false);
    expect(await svc([roleRow('team_lead')]).can(user, { ...c, resourceId: 't1' })).toBe(false);
  });
  it('owner role row never grants', async () => {
    const s = svc([{ scopeType: '', scopeId: '', role: { code: 'owner', rolePermissions: [{ permission: { code: 'audit.logs.read' } }] } }]);
    expect(await s.can(user, { permissionKey: 'audit.logs.read', resourceType: 'platform', resourceId: 'platform' })).toBe(false);
  });
});
