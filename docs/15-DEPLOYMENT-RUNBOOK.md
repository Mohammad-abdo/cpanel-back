# Deployment Runbook

Status: written 2026-11-15 from the working local setup; NOT rehearsed on a staging VPS yet. Source: required.md section 14.

## Principles (required.md 14)
Isolate the control plane; MFA and least privilege; encrypted secrets; the dashboard going down must never stop customer applications; agents reconnecting must never replay stale jobs.

## 1. Prepare (once)
1. A separate VPS (or VM) for the panel; MySQL 8 reachable only from it.
2. Node.js 22 or newer.
3. Secrets, generated on the server and kept in a password manager and an offline copy:
   - `SESSION_SECRET`: long random string.
   - `CREDENTIAL_ENCRYPTION_KEY`: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` (encrypts SSH passwords and environment variables; losing it makes them unreadable).
   - `BACKUP_ENCRYPTION_KEY`: same format, different value.
   - `EMERGENCY_RECOVERY_CODE_SHA256`: SHA-256 of an offline recovery code.
4. `cpanel-back/.env`: `NODE_ENV=production`, `HOST=127.0.0.1`, `PORT=4000`, `DATABASE_URL=mysql://user:pass@127.0.0.1:3306/nodeteam_control`, plus the secrets above. Never commit it.

## 2. Install or upgrade
```
cd cpanel-back
npm ci
npx prisma migrate deploy      # additive migrations only
npm run prisma:seed            # first install only: creates the Owner; change the password at first login
npm run drill:recovery         # before every upgrade: proves the database backup restores
cd ../cpanel-admin
npm ci
npm run build                  # static files in dist/
```

## 3. Run
- API: a process manager (pm2 or systemd) running `npm start` in cpanel-back. The background scheduler runs inside it (`NT_JOBS_ENABLED=false` to turn it off on extra API instances).
- Web: Nginx serves `cpanel-admin/dist`, proxies `/api/` to `127.0.0.1:4000`, and upgrades WebSockets for `/api/v1/servers/terminal`:
  ```
  location /api/ {
    proxy_pass http://127.0.0.1:4000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 3600s;   # terminal sessions
    client_max_body_size 25m;   # file uploads (20 MB limit in the API)
  }
  ```
- HTTPS only (the terminal then uses wss://).

## 4. Verify after every deploy
```
curl -s https://panel.example.com/api/v1/health      # {"data":{"status":"ok"}}
```
Then sign in, open Servers, open one server's details page, and check the scheduler line in the API log (`[jobs] scheduler started`). On a staging copy with demo data: `npm run smoke`, `npm run test:security`, `npm run drill:security`.

## 5. Roll back
- Code: redeploy the previous release; migrations are additive, so the previous code runs on the newer schema.
- Data: restore the dump taken by `npm run drill:recovery` (kept in `.data/drills/`), or the regular database backup, into a new database, check it, then point `DATABASE_URL` at it.
- Stopping the panel never stops customer applications: they do not depend on it.

## 6. Emergency Owner access
If the Owner cannot sign in, use break-glass (`POST /platform/break-glass/activate`) with the offline recovery code; it is time-limited and audited.
