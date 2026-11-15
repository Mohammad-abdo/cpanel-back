/**
 * Executor port for operations. Real execution (git pull, pm2 restart, rollback) happens on the
 * server Agent and is NOT_RUN in this repository. The default executor only simulates.
 */
export function createSimulatedExecutor() {
  return {
    name: 'simulated',
    /** Never touches a server. Returns a deterministic dry-run result. */
    async execute(job, { attemptId }) {
      return {
        result: 'SIMULATED',
        detail: { dryRun: true, action: job.action, attemptId, note: 'Agent-side execution is NOT_RUN' },
      };
    },
  };
}
