import { describe, expect, it, vi } from 'vitest';
import { createHash, randomUUID } from 'node:crypto';
import { createLogsService } from '../src/modules/logs/logs.service.js';
import { createInMemoryLogStore } from '../src/modules/logs/logs.store.js';
import { redactText, redactDeep } from '../src/modules/logs/logs.redaction.js';
import { createErrorsService } from '../src/modules/monitoring/monitoring.errors.js';

const owner = { id: 'owner-1', isOwner: true };
const projectId = randomUUID();
const envId = randomUUID();
const sourceId = randomUUID();

function makePrisma() {
  return {
    logSource: {
      findMany: vi.fn().mockResolvedValue([]),
      findUnique: vi.fn(),
      create: vi.fn(),
    },
    project: { findUnique: vi.fn() },
    projectEnvironment: { findUnique: vi.fn() },
    deployment: { findUnique: vi.fn() },
    logBookmark: {
      create: vi.fn(),
      findMany: vi.fn().mockResolvedValue([]),
      findUnique: vi.fn(),
      delete: vi.fn(),
    },
    errorGroup: {
      findUnique: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
      findMany: vi.fn().mockResolvedValue([]),
    },
    projectMember: { findMany: vi.fn().mockResolvedValue([]) },
    resourceGrant: { findMany: vi.fn().mockResolvedValue([]) },
  };
}

describe('log redaction', () => {
  it('strips tokens before they can be stored or shown', () => {
    expect(redactText('Authorization: Bearer abcdefghijklmnop')).toContain('[REDACTED]');
    expect(redactText('password=super-secret')).toContain('[REDACTED]');
    expect(redactDeep({ apiKey: 'sk-1234567890123456', nested: { token: 'x' } })).toEqual({
      apiKey: '[REDACTED]',
      nested: { token: '[REDACTED]' },
    });
  });
});

describe('logs.service ingest and scope', () => {
  it('stores redacted entries under the source project labels', async () => {
    const prisma = makePrisma();
    prisma.logSource.findUnique.mockResolvedValue({
      id: sourceId,
      projectId,
      serverId: null,
      kind: 'application',
      labelJson: { environmentId: envId },
    });
    prisma.project.findUnique.mockResolvedValue({ id: projectId, serverId: 'srv-1' });
    const store = createInMemoryLogStore();
    const logs = createLogsService({ prisma, store });

    const result = await logs.ingest(
      {
        sourceId,
        entries: [
          {
            level: 'error',
            message: 'failed with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaa.bbb and password=hunter2',
          },
        ],
      },
      { type: 'user', actor: owner },
    );

    expect(result.accepted).toBe(1);
    const [row] = store.query({ projectId }, { limit: 10 });
    expect(row.labels.projectId).toBe(projectId);
    expect(row.labels.environmentId).toBe(envId);
    expect(row.message).not.toMatch(/hunter2|eyJhbGci/);
    expect(row.message).toContain('[REDACTED]');
  });

  it('rejects cross-project search for non-owners', async () => {
    const prisma = makePrisma();
    const store = createInMemoryLogStore();
    const rbac = { can: vi.fn().mockResolvedValue(false) };
    const logs = createLogsService({ prisma, store, rbac });
    await expect(
      logs.search({ projectId, environmentId: envId, limit: 10 }, { id: 'u2', isOwner: false }),
    ).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });

  it('keeps injected errors inside the correct project group', async () => {
    const prisma = makePrisma();
    prisma.errorGroup.findUnique.mockResolvedValue(null);
    prisma.errorGroup.create.mockImplementation(async ({ data }) => ({ id: 'eg1', ...data }));
    const errors = createErrorsService({ prisma });
    const fp = createHash('sha256').update('boom\n').digest('hex').slice(0, 32);

    const group = await errors.observe({
      entry: { level: 'error', message: 'boom', ts: new Date() },
      labels: { projectId },
    });

    expect(group.projectId).toBe(projectId);
    expect(group.fingerprint).toBe(fp);
    expect(prisma.errorGroup.create).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ projectId, fingerprint: fp }) }),
    );
  });
});
