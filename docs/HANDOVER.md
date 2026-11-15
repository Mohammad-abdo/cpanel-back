# HANDOVER

Read sources and task registry. After roadmap approval begin TASK-001. Validate dependencies; implement scoped work; record self-review and independent review honestly; execute tests and update registry/status. No production deployment, restore, firewall or secret changes without explicit authorization.

## Demo data

Opt-in, development only. With the local API running, run `npm run seed:demo`. It logs in as the seeded Owner (`NT_OWNER_EMAIL` / `NT_OWNER_PASSWORD`, defaults from `apps/api/prisma/seed.js`) and fills the local database through the real API: servers with enrolled demo agents and backdated metrics, projects, deployments, domains, certificates, databases, backups, incidents, alert rules, logs, reports and an access review.

The script refuses to run unless `NT_API` points at localhost/127.0.0.1 and `NODE_ENV` is not `production`. Every created name, alias or slug is prefixed `demo-`. It is idempotent (existing records are skipped) and prints a created/skipped/failed table. Steps that need approvals or an unavailable feature are logged as failed and skipped. There is no delete path: remove unwanted demo rows directly in the database.
