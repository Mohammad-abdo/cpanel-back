import { createApp } from './app.js';
import { parseEnv } from './config/env.js';
const env = parseEnv();
const server = createApp().listen(env.PORT, env.HOST, () => {
  console.info(`NodeTeam API listening on http://${env.HOST}:${env.PORT}`);
});
server.on('error', () => {
  console.error('API listener failed. Check host and port configuration.');
  process.exitCode = 1;
});
function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10000).unref();
}
process.once('SIGTERM', shutdown);
process.once('SIGINT', shutdown);
