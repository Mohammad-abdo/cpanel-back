import { createStreamSession } from './logs.stream.js';

export function createLogsController(logsService) {
  return {
    async listSources(req, res) {
      res.status(200).json({ data: await logsService.listSources(req.validated.query, req.user) });
    },

    async registerSource(req, res) {
      res.status(201).json({ data: await logsService.registerSource(req.validated.body, req.user) });
    },

    /** Agent-authenticated ingestion (req.agent set by the route middleware). */
    async ingestAgent(req, res) {
      const result = await logsService.ingest(req.validated.body, { type: 'agent', serverId: req.agent.serverId });
      res.status(202).json({ data: result });
    },

    async ingestManual(req, res) {
      const result = await logsService.ingest(req.validated.body, { type: 'user', actor: req.user });
      res.status(202).json({ data: result });
    },

    async search(req, res) {
      res.status(200).json({ data: await logsService.search(req.validated.query, req.user) });
    },

    async export(req, res) {
      const file = await logsService.export(req.validated.query, req.user);
      res.setHeader('Content-Type', file.contentType);
      res.setHeader('Content-Disposition', `attachment; filename="${file.filename}"`);
      res.status(200).send(file.body);
    },

    /** Server-sent events with Last-Event-ID reconnect and bounded backpressure. */
    async stream(req, res) {
      const lastHeader = Number.parseInt(req.get('last-event-id') ?? '', 10);
      const query = {
        ...req.validated.query,
        lastEventId: req.validated.query.lastEventId ?? (Number.isFinite(lastHeader) ? lastHeader : undefined),
      };
      const session = createStreamSession({
        send: ({ event, id, data }) =>
          res.write(`${id !== undefined ? `id: ${id}\n` : ''}event: ${event}\ndata: ${JSON.stringify(data)}\n\n`),
      });
      res.status(200).set({
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
        'X-Accel-Buffering': 'no',
      });
      let close;
      try {
        close = await logsService.openStream(query, req.user, session);
      } catch (error) {
        res.removeHeader('Content-Type'); // let the error handler answer with JSON
        throw error;
      }
      res.flushHeaders?.();
      res.on('drain', () => session.resume());
      const heartbeat = setInterval(() => res.write(': ping\n\n'), 15000);
      heartbeat.unref?.();
      req.on('close', () => {
        clearInterval(heartbeat);
        close();
      });
    },

    async createBookmark(req, res) {
      res.status(201).json({ data: await logsService.createBookmark(req.validated.body, req.user) });
    },

    async listBookmarks(req, res) {
      res.status(200).json({ data: await logsService.listBookmarks(req.user) });
    },

    async deleteBookmark(req, res) {
      res.status(200).json({ data: await logsService.deleteBookmark(req.validated.params.id, req.user) });
    },
  };
}
