/**
 * Load test (TASK-029, local only): N concurrent virtual users call the main read endpoints for D seconds.
 * Reports throughput, latency percentiles and errors per endpoint.
 *   npm run test:load            (defaults: 25 users, 20 seconds)
 *   NT_LOAD_USERS=50 NT_LOAD_SECONDS=30 npm run test:load
 * Budget (pass/fail): p95 under NT_LOAD_P95_MS (default 500 ms) and zero 5xx errors.
 */
const API = process.env.NT_API || 'http://127.0.0.1:4000/api/v1';
if (!/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(API)) {
  console.error(`Refusing to run against non-local API: ${API}`);
  process.exit(1);
}
const USERS = Number(process.env.NT_LOAD_USERS || 25);
const SECONDS = Number(process.env.NT_LOAD_SECONDS || 20);
const P95_BUDGET = Number(process.env.NT_LOAD_P95_MS || 500);

const login = await fetch(`${API}/auth/login`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ email: process.env.NT_OWNER_EMAIL || 'owner@localhost.local', password: process.env.NT_OWNER_PASSWORD || 'change-me-now-please' }),
}).then((r) => r.json());
const token = login.data.token;
const auth = { authorization: `Bearer ${token}` };
const first = async (p) => (await fetch(API + p, { headers: auth }).then((r) => r.json())).data?.[0];
const project = await first('/projects');
const server = await first('/servers');

const endpoints = [
  '/servers',
  '/projects',
  '/deployments?limit=20',
  '/domains',
  '/certificates',
  '/incidents',
  '/audit/events?limit=20',
  '/monitoring/fleet?hours=6',
  ...(project ? [`/projects/${project.id}`, `/projects/${project.id}/overview`] : []),
  ...(server ? [`/servers/${server.id}`, `/servers/${server.id}/metrics`] : []),
];

const stats = new Map(endpoints.map((e) => [e, { lat: [], codes: {} }]));
const deadline = Date.now() + SECONDS * 1000;
let total = 0;

async function user(i) {
  let n = i;
  while (Date.now() < deadline) {
    const ep = endpoints[n++ % endpoints.length];
    const t0 = performance.now();
    let code;
    try {
      const r = await fetch(API + ep, { headers: auth });
      await r.arrayBuffer();
      code = r.status;
    } catch {
      code = 'net';
    }
    const s = stats.get(ep);
    s.lat.push(performance.now() - t0);
    s.codes[code] = (s.codes[code] ?? 0) + 1;
    total += 1;
  }
}

console.log(`Load test: ${USERS} users x ${SECONDS}s against ${endpoints.length} endpoints`);
const started = Date.now();
await Promise.all(Array.from({ length: USERS }, (_, i) => user(i)));
const elapsed = (Date.now() - started) / 1000;

const pct = (arr, p) => {
  const a = [...arr].sort((x, y) => x - y);
  return a.length ? a[Math.min(a.length - 1, Math.floor((p / 100) * a.length))] : 0;
};
const all = [...stats.values()].flatMap((s) => s.lat);
let serverErrors = 0;
console.log('\nendpoint'.padEnd(52) + 'reqs   p50    p95    p99   codes');
for (const [ep, s] of stats) {
  const codes = Object.entries(s.codes).map(([c, n]) => `${c}:${n}`).join(' ');
  serverErrors += Object.entries(s.codes).filter(([c]) => c === 'net' || Number(c) >= 500).reduce((x, [, n]) => x + n, 0);
  console.log(`${ep.slice(0, 50).padEnd(50)} ${String(s.lat.length).padStart(5)} ${pct(s.lat, 50).toFixed(0).padStart(5)} ${pct(s.lat, 95).toFixed(0).padStart(6)} ${pct(s.lat, 99).toFixed(0).padStart(6)}   ${codes}`);
}
const p95 = pct(all, 95);
console.log(`\ntotal ${total} requests in ${elapsed.toFixed(1)}s = ${(total / elapsed).toFixed(0)} req/s; p50 ${pct(all, 50).toFixed(0)} ms, p95 ${p95.toFixed(0)} ms, p99 ${pct(all, 99).toFixed(0)} ms; 5xx/network errors ${serverErrors}`);
const ok = p95 <= P95_BUDGET && serverErrors === 0;
console.log(`RESULT: ${ok ? 'PASS' : 'FAIL'} (budget p95 <= ${P95_BUDGET} ms, 0 server errors)`);
process.exitCode = ok ? 0 : 1;
