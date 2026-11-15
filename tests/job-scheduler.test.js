import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { createScheduler } from '../src/jobs/scheduler.js';
import { buildJobs, parseJobConfig } from '../src/jobs/jobs.js';

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

const quiet = { log: () => {}, random: () => 0 };

describe('job scheduler', () => {
  it('runs a job on its interval', async () => {
    const run = vi.fn().mockResolvedValue([]);
    const s = createScheduler({ ...quiet, jobs: [{ name: 'a', intervalMs: 1000, run }] });
    s.start();
    await vi.advanceTimersByTimeAsync(3000);
    expect(run).toHaveBeenCalledTimes(4);
    await s.stop();
  });

  it('guards against overlap', async () => {
    let release;
    const run = vi.fn(() => new Promise((r) => (release = r)));
    const s = createScheduler({ ...quiet, jobs: [{ name: 'slow', intervalMs: 1000, run }] });
    s.start();
    await vi.advanceTimersByTimeAsync(3500);
    expect(run).toHaveBeenCalledTimes(1);
    expect(s.status().slow.skipped).toBeGreaterThanOrEqual(2);
    release();
    await s.stop();
  });

  it('isolates errors, audits them, and keeps other jobs running', async () => {
    const bad = vi.fn().mockRejectedValue(new Error('boom'));
    const good = vi.fn().mockResolvedValue({});
    const onFailure = vi.fn().mockRejectedValue(new Error('audit down'));
    const s = createScheduler({ ...quiet, onFailure, jobs: [{ name: 'bad', intervalMs: 1000, run: bad }, { name: 'good', intervalMs: 1000, run: good }] });
    s.start();
    await vi.advanceTimersByTimeAsync(2000);
    expect(good).toHaveBeenCalledTimes(3);
    expect(bad).toHaveBeenCalledTimes(3);
    expect(onFailure).toHaveBeenCalledWith(expect.objectContaining({ job: 'bad' }));
    expect(s.status().bad.failures).toBe(3);
    await s.stop();
  });

  it('stops timers and drains in-flight work on shutdown', async () => {
    let release;
    const run = vi.fn(() => new Promise((r) => (release = r)));
    const s = createScheduler({ ...quiet, jobs: [{ name: 'a', intervalMs: 1000, run }] });
    s.start();
    await vi.advanceTimersByTimeAsync(0);
    const stopping = s.stop({ timeoutMs: 5000 });
    release();
    expect(await stopping).toEqual({ drained: true });
    await vi.advanceTimersByTimeAsync(5000);
    expect(run).toHaveBeenCalledTimes(1);
  });

  it('applies jitter to the first run only', async () => {
    const run = vi.fn().mockResolvedValue(null);
    const s = createScheduler({ log: () => {}, random: () => 0.5, jitterRatio: 0.2, jobs: [{ name: 'a', intervalMs: 1000, run }] });
    s.start();
    await vi.advanceTimersByTimeAsync(99);
    expect(run).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(2);
    expect(run).toHaveBeenCalledTimes(1);
    await s.stop();
  });
});

describe('job config', () => {
  it('uses safe defaults and honours env overrides', () => {
    const c = parseJobConfig({ NT_JOB_ALERT_EVAL_MS: '5000', NT_JOB_CERT_SCAN_MS: 'abc', NT_JOB_REPORTS_MS: '10' });
    expect(c.intervals['alerts.evaluateAll']).toBe(5000);
    expect(c.intervals['certificates.scanExpiry']).toBe(6 * 3600_000);
    expect(c.intervals['reports.runDue']).toBe(60_000);
    expect(c.enabled).toBe(true);
    expect(parseJobConfig({ NT_JOBS_ENABLED: 'false' }).enabled).toBe(false);
  });

  it('builds jobs that call the service methods; security.sync runs as the system actor by default', async () => {
    const services = {
      operations: { expireStale: vi.fn().mockResolvedValue(1) },
      alerts: { evaluateAll: vi.fn().mockResolvedValue([]), escalateDue: vi.fn().mockResolvedValue([]) },
      reports: { runDue: vi.fn().mockResolvedValue([]) },
      certificates: { scanExpiry: vi.fn().mockResolvedValue({}) },
      backups: { runDue: vi.fn().mockResolvedValue([]), verifyLatest: vi.fn().mockResolvedValue([]), planRetention: vi.fn().mockResolvedValue({ remove: [1], keep: [] }) },
      prisma: { backupPolicy: { findMany: vi.fn().mockResolvedValue([{ id: 'p1' }]) } },
      security: { sync: vi.fn().mockResolvedValue({}) },
      accessReviews: { startDue: vi.fn().mockResolvedValue({ started: false }) },
    };
    const jobs = buildJobs(services, parseJobConfig({}));
    expect(jobs.map((j) => j.name)).toEqual(expect.arrayContaining(['security.sync', 'accessReviews.startDue']));
    for (const j of jobs) await j.run({ at: new Date() });
    expect(services.operations.expireStale).toHaveBeenCalled();
    expect(services.security.sync).toHaveBeenCalledWith({ sinceMinutes: 60 }, expect.objectContaining({ system: true }));
    expect(services.accessReviews.startDue).toHaveBeenCalledWith(expect.any(Date), { everyDays: 90 });
    expect(buildJobs(services, parseJobConfig({ NT_ACCESS_REVIEW_DAYS: '0' })).map((j) => j.name)).not.toContain('accessReviews.startDue');
    expect(services.backups.planRetention).toHaveBeenCalledWith('p1', expect.objectContaining({ isOwner: true, system: true }));
    const withSec = buildJobs(services, parseJobConfig({ NT_SECURITY_SYNC_ACTOR_ID: 'u1' }));
    await withSec.find((j) => j.name === 'security.sync').run({});
    expect(services.security.sync).toHaveBeenCalledWith({ sinceMinutes: 60 }, { id: 'u1', isOwner: true });
  });
});
