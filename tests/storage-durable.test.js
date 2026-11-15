import { describe, it, expect } from 'vitest';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { createPrismaLogStore } from '../src/modules/logs/logs.prisma-store.js';
import { createFileArtifactStore } from '../src/modules/reports/reports.artifacts.js';

function mockPrisma() {
  const rows = [];
  let seq = 0;
  return {
    rows,
    logEntry: {
      async create({ data }) {
        const r = { id: `i${seq}`, ...data, seq: ++seq };
        rows.push(r);
        return r;
      },
      async findMany({ where, take }) {
        return rows
          .filter((r) => !where.projectId || r.projectId === where.projectId)
          .sort((a, b) => b.seq - a.seq)
          .slice(0, take);
      },
      async deleteMany({ where }) {
        const before = rows.length;
        for (let i = rows.length - 1; i >= 0; i -= 1) if (rows[i].occurredAt < where.occurredAt.lt) rows.splice(i, 1);
        return { count: before - rows.length };
      },
    },
  };
}
const entry = (projectId, message, ts = new Date()) => ({ ts, level: 'error', message, labels: { projectId, kind: 'app' } });

describe('prisma log store', () => {
  it('redacts before storage, scopes by project, prunes', async () => {
    const prisma = mockPrisma();
    const store = createPrismaLogStore(prisma);
    await store.append([entry('p1', 'login password=hunter2 token=abcdef1234567890abcdef'), entry('p2', 'other')]);
    expect(prisma.rows[0].message).not.toContain('hunter2');
    const p1 = await store.queryDurable({ projectId: 'p1' }, { limit: 10 });
    expect(p1).toHaveLength(1);
    expect(p1[0].labels.projectId).toBe('p1');
    await store.append([entry('p1', 'old', new Date(Date.now() - 40 * 86400000))]);
    expect((await store.pruneOlderThan(30)).deleted).toBe(1);
  });
  it('fails with SCHEMA_REQUIRED when delegate is missing', async () => {
    const store = createPrismaLogStore({});
    await expect(store.append([entry('p1', 'x')])).rejects.toMatchObject({ status: 501, code: 'SCHEMA_REQUIRED' });
  });
});

describe('file artifact store', () => {
  it('round-trips, blocks traversal, enforces size and expiry', async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'nt-art-'));
    try {
      let t = new Date('2026-01-01T00:00:00Z');
      const store = createFileArtifactStore({ dir, maxBytes: 100, now: () => t });
      await store.put('../../evil/../x', 'hello', { contentType: 'text/plain', expiresAt: new Date('2026-01-02T00:00:00Z') });
      const got = await store.get('../../evil/../x');
      expect(got.body).toBe('hello');
      expect(got.checksum).toMatch(/^[0-9a-f]{64}$/);
      expect((await readdir(dir)).every((n) => /^[0-9a-f]{64}\.(bin|json)$/.test(n))).toBe(true);
      await expect(store.put('big', 'x'.repeat(101), {})).rejects.toMatchObject({ code: 'ARTIFACT_TOO_LARGE' });
      t = new Date('2026-01-03T00:00:00Z');
      expect((await store.pruneExpired()).removed).toBe(1);
      expect(await store.get('../../evil/../x')).toBeNull();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
