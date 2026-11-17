import { respond } from '../platform/platform.http.js';

export function createServerAccessController(svc) {
  const id = (req) => req.validated.params.id;
  return {
    async addServer(req, res) {
      res.status(201).json({ data: await svc.addServer(req.validated.body, req.user) });
    },
    async getCredential(req, res) {
      res.status(200).json({ data: await svc.getCredential(id(req), req.user) });
    },
    async setCredential(req, res) {
      res.status(200).json({ data: await svc.setCredential(id(req), req.validated.body, req.user) });
    },
    async removeCredential(req, res) {
      res.status(200).json({ data: await svc.removeCredential(id(req), req.user) });
    },
    async test(req, res) {
      res.status(200).json({ data: await svc.test(id(req), req.user) });
    },
    async list(req, res) {
      res.status(200).json({ data: await svc.list(id(req), req.validated.query.path, req.user) });
    },
    async read(req, res) {
      res.status(200).json({ data: await svc.read(id(req), req.validated.query.path, req.user) });
    },
    async write(req, res) {
      res.status(200).json({ data: await svc.write(id(req), req.validated.body, req.user) });
    },
    async search(req, res) {
      res.status(200).json({ data: await svc.search(id(req), req.validated.query, req.user) });
    },
    async upload(req, res) {
      const bytes = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
      res.status(201).json({ data: await svc.upload(id(req), { path: req.validated.query.path, bytes }, req.user) });
    },
    async download(req, res) {
      const file = await svc.download(id(req), req.validated.query.path, req.user);
      const safeName = file.name.replace(/[^\w.\- ]+/g, '_') || 'download';
      res.set('Content-Type', 'application/octet-stream');
      res.set('Content-Disposition', `attachment; filename="${safeName}"`);
      res.status(200).send(file.bytes);
    },
    async mkdir(req, res) {
      res.status(201).json({ data: await svc.mkdir(id(req), req.validated.body.path, req.user) });
    },
    async rename(req, res) {
      res.status(200).json({ data: await svc.rename(id(req), req.validated.body, req.user) });
    },
    async remove(req, res) {
      res.status(200).json({ data: await svc.remove(id(req), req.validated.query, req.user) });
    },
    async info(req, res) {
      res.status(200).json({ data: await svc.info(id(req), req.user) });
    },
    async service(req, res) {
      res.status(200).json({ data: await svc.service(id(req), req.validated.body, req.user) });
    },
    async pm2List(req, res) {
      res.status(200).json({ data: await svc.pm2List(id(req), req.user) });
    },
    async pm2Logs(req, res) {
      res.status(200).json({ data: await svc.pm2Logs(id(req), req.validated.query, req.user) });
    },
    async pm2Control(req, res) {
      respond(res, await svc.pm2Control(id(req), req.validated.body, req.user));
    },
    async htop(req, res) {
      res.status(200).json({ data: await svc.htop(id(req), req.user) });
    },
    async listeningPorts(req, res) {
      res.status(200).json({ data: await svc.listeningPorts(id(req), req.user) });
    },
    async ticket(req, res) {
      respond(res, await svc.createTicket(id(req), req.validated.body ?? {}, req.user), 201);
    },
    async scanInventory(req, res) {
      res.status(200).json({ data: await svc.scanInventory(id(req), req.user) });
    },
    async importInventory(req, res) {
      res.status(200).json({ data: await svc.importInventory(id(req), req.validated.body ?? {}, req.user) });
    },
    async dbSchemas(req, res) {
      const { id: serverId, engine } = req.validated.params;
      res.status(200).json({ data: await svc.dbBrowse(serverId, { engine, action: 'schemas' }, req.user) });
    },
    async dbTables(req, res) {
      const { id: serverId, engine } = req.validated.params;
      res.status(200).json({
        data: await svc.dbBrowse(serverId, { engine, action: 'tables', db: req.validated.query.db }, req.user),
      });
    },
    async dbColumns(req, res) {
      const { id: serverId, engine } = req.validated.params;
      const { db, table } = req.validated.query;
      res.status(200).json({
        data: await svc.dbBrowse(serverId, { engine, action: 'columns', db, table }, req.user),
      });
    },
    async dbRows(req, res) {
      const { id: serverId, engine } = req.validated.params;
      const { db, table, limit, offset } = req.validated.query;
      res.status(200).json({
        data: await svc.dbBrowse(serverId, { engine, action: 'rows', db, table, limit, offset }, req.user),
      });
    },
    async dbQuery(req, res) {
      const { id: serverId, engine } = req.validated.params;
      const { sql, db } = req.validated.body;
      res.status(200).json({
        data: await svc.dbBrowse(serverId, { engine, action: 'query', sql, db }, req.user),
      });
    },
  };
}
