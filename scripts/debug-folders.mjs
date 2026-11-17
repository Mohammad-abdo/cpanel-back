/**
 * Local webmail folder probe. Never hardcode mailbox passwords.
 *
 * Usage (PowerShell):
 *   $env:WM_ADDRESS='info@example.com'; $env:WM_PASSWORD='...'; node scripts/debug-folders.mjs
 */
const address = process.env.WM_ADDRESS;
const password = process.env.WM_PASSWORD;
const base = process.env.WM_BASE || 'http://127.0.0.1:2096';

if (!address || !password) {
  console.error('Set WM_ADDRESS and WM_PASSWORD (optional WM_BASE). Do not commit secrets.');
  process.exit(1);
}

const login = await fetch(`${base}/wm/v1/auth/login`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ address, password }),
});
const setCookie = login.headers.getSetCookie?.() || [];
const cookie = setCookie.map((c) => c.split(';')[0]).join('; ');
console.log('login', login.status, await login.json().catch(() => ({})));
const folders = await fetch(`${base}/wm/v1/mail/folders`, { headers: { Cookie: cookie } });
const body = await folders.json().catch(() => ({}));
console.log('folders', folders.status, JSON.stringify(body, null, 2));
