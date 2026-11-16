import { respond } from '../platform/platform.http.js';

export function createDatabasesController(svc) {
  return {
    async list(req, res) {
      res.status(200).json({ data: await svc.list(req.validated.query, req.user) });
    },
    async instances(req, res) {
      res.status(200).json({ data: await svc.listInstances(req.user) });
    },
    async getInstance(req, res) {
      res.status(200).json({ data: await svc.getInstance(req.validated.params.id, req.user) });
    },
    async createInstance(req, res) {
      respond(res, await svc.createInstance(req.validated.body, req.user), 201);
    },
    async setInstanceLogin(req, res) {
      res.status(200).json({ data: await svc.setInstanceLogin(req.validated.params.id, req.validated.body, req.user) });
    },
    async clearInstanceLogin(req, res) {
      res.status(200).json({ data: await svc.clearInstanceLogin(req.validated.params.id, req.user) });
    },
    async liveSchemas(req, res) {
      res.status(200).json({
        data: await svc.liveBrowse(req.validated.params.id, { action: 'schemas' }, req.user),
      });
    },
    async liveTables(req, res) {
      res.status(200).json({
        data: await svc.liveBrowse(req.validated.params.id, { action: 'tables', db: req.validated.query.db }, req.user),
      });
    },
    async liveColumns(req, res) {
      const { db, table } = req.validated.query;
      res.status(200).json({
        data: await svc.liveBrowse(req.validated.params.id, { action: 'columns', db, table }, req.user),
      });
    },
    async liveRows(req, res) {
      const { db, table, limit, offset } = req.validated.query;
      res.status(200).json({
        data: await svc.liveBrowse(req.validated.params.id, { action: 'rows', db, table, limit, offset }, req.user),
      });
    },
    async liveQuery(req, res) {
      const { sql, db } = req.validated.body;
      res.status(200).json({
        data: await svc.liveBrowse(req.validated.params.id, { action: 'query', sql, db }, req.user),
      });
    },
    async liveDump(req, res) {
      const dump = await svc.liveDump(req.validated.params.id, req.validated.body ?? {}, req.user);
      res.setHeader('Content-Type', dump.contentType || 'application/sql; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${dump.filename}"`);
      res.setHeader('X-Dump-Size', String(dump.size));
      res.setHeader('X-Dump-Engine', dump.engine);
      if (dump.db) res.setHeader('X-Dump-Db', dump.db);
      res.status(200).send(dump.bytes);
    },
    async liveRestore(req, res) {
      const bytes = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body ?? []);
      const { db, confirm } = req.validated.query;
      res.status(200).json({
        data: await svc.liveRestore(req.validated.params.id, { db: db || null, bytes, confirm }, req.user),
      });
    },
    async create(req, res) {
      respond(res, await svc.create(req.validated.body, req.user), 201);
    },
    async createUser(req, res) {
      respond(res, await svc.createUser(req.validated.params.id, req.validated.body, req.user), 201);
    },
    async drop(req, res) {
      respond(res, await svc.drop(req.validated.params.id, req.validated.body, req.user));
    },
  };
}
