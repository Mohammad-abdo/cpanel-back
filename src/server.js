import { createApp } from './app.js';
import { parseEnv } from './config/env.js';
import { startJobs } from './jobs/index.js';
import { attachTerminal } from './modules/server-access/server-access.terminal.js';
import { serverAccessService } from './modules/server-access/server-access.routes.js';
const env = parseEnv();
const server = createApp().listen(env.PORT, env.HOST, () => {
  console.info(`NodeTeam API listening on http://${env.HOST}:${env.PORT}`);
});
server.on('error', () => {
  console.error('API listener failed. Check host and port configuration.');
  process.exitCode = 1;
});
attachTerminal(server, serverAccessService);
const scheduler = startJobs();
function shutdown() {
  const jobsDone = scheduler ? scheduler.stop({ timeoutMs: 8000 }) : Promise.resolve();
  jobsDone.finally(() => server.close(() => process.exit(0)));
  setTimeout(() => process.exit(1), 10000).unref();
}
process.once('SIGTERM', shutdown);
process.once('SIGINT', shutdown);
