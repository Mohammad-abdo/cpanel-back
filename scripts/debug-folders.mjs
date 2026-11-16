const login = await fetch('http://127.0.0.1:2096/wm/v1/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ address: 'info@rasad.nodeteam.site', password: 'NtWm-af099ccf3429' }),
});
const setCookie = login.headers.getSetCookie?.() || [];
const cookie = setCookie.map((c) => c.split(';')[0]).join('; ');
console.log('login', login.status, await login.json().catch(() => ({})));
const folders = await fetch('http://127.0.0.1:2096/wm/v1/mail/folders', { headers: { Cookie: cookie } });
const body = await folders.json().catch(() => ({}));
console.log('folders', folders.status, JSON.stringify(body, null, 2));
