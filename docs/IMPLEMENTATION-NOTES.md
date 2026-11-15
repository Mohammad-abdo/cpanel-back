# Local backend foundation

Run npm install, then npm run dev from the repository root. The API binds 127.0.0.1:4000 by default. Optional configuration is apps/api/.env (copy .env.example). GET /api/v1/health returns liveness only. npm test runs the current suite. npm run module:create -- projects generates four module files; implement permission and input contracts before explicitly mounting it.

Dependency versions are pinned by package-lock.json. Express async error behavior follows https://expressjs.com/en/guide/error-handling.html . Prisma integration is deferred to the schema task; its current driver/config requirements must be checked before introducing persistence: https://www.prisma.io/docs/orm/v7/core-concepts/supported-databases/mysql .

No production credentials, database or remote Agent was available or used. No fake inventory or business CRUD endpoints were added.
