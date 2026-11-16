import { createWebmailApp } from './webmail-app.js';
import { parseEnv } from './config/env.js';

const env = parseEnv();
const host = env.WEBMAIL_HOST;
const port = env.WEBMAIL_PORT;

const server = createWebmailApp().listen(port, host, () => {
  console.info(`NodeTeam Webmail listening on http://${host}:${port}`);
});

server.on('error', (err) => {
  console.error('Webmail listener failed:', err?.message || err);
  process.exitCode = 1;
});

function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.once('SIGTERM', shutdown);
process.once('SIGINT', shutdown);
