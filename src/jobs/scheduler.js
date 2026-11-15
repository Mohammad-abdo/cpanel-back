/**
 * Dependency-free interval scheduler for background jobs (replaces the former apps/worker).
 * - Each job runs immediately (after a small first-run jitter), then every intervalMs.
 * - Overlap guard: a job still running when its next tick arrives is skipped, not stacked.
 * - Error isolation: a failing job never stops other jobs; failures go to onFailure (which may itself fail).
 * - stop() clears timers and waits for in-flight runs up to timeoutMs.
 */
export function createScheduler({ jobs, log = console.info, onFailure = null, random = Math.random, jitterRatio = 0.1 }) {
  const state = {};
  const timers = new Set();
  const inflight = new Set();
  let stopped = false;

  for (const j of jobs) state[j.name] = { runs: 0, failures: 0, skipped: 0, running: false, lastRunAt: null, lastError: null };

  async function tick(job) {
    if (stopped) return;
    const s = state[job.name];
    if (s.running) {
      s.skipped += 1;
      return;
    }
    s.running = true;
    s.lastRunAt = new Date();
    const p = (async () => {
      try {
        await job.run({ at: s.lastRunAt });
        s.runs += 1;
      } catch (err) {
        s.failures += 1;
        s.lastError = err?.message ?? String(err);
        log(`[jobs] ${job.name} failed: ${s.lastError}`);
        if (onFailure) {
          try {
            await onFailure({ job: job.name, error: s.lastError, at: s.lastRunAt });
          } catch {
            /* failure reporting must never break the scheduler */
          }
        }
      } finally {
        s.running = false;
      }
    })();
    inflight.add(p);
    p.finally(() => inflight.delete(p));
    return p;
  }

  return {
    start() {
      stopped = false;
      for (const job of jobs) {
        const delay = Math.floor(job.intervalMs * jitterRatio * random());
        const first = setTimeout(() => {
          timers.delete(first);
          tick(job);
          const every = setInterval(() => tick(job), job.intervalMs);
          timers.add(every);
        }, delay);
        timers.add(first);
      }
      log(`[jobs] scheduler started: ${jobs.map((j) => j.name).join(', ')}`);
    },

    async stop({ timeoutMs = 10_000 } = {}) {
      stopped = true;
      for (const t of timers) {
        clearTimeout(t);
        clearInterval(t);
      }
      timers.clear();
      if (!inflight.size) return { drained: true };
      let timer;
      const timeout = new Promise((r) => {
        timer = setTimeout(() => r({ drained: false }), timeoutMs);
      });
      const result = await Promise.race([Promise.allSettled([...inflight]).then(() => ({ drained: true })), timeout]);
      clearTimeout(timer);
      return result;
    },

    status() {
      return Object.fromEntries(Object.entries(state).map(([k, v]) => [k, { ...v }]));
    },
  };
}
