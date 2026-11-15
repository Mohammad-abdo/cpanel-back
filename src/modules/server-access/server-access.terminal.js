import { WebSocketServer } from 'ws';

export const TERMINAL_PATH = '/api/v1/servers/terminal';
const MAX_TRANSCRIPT_LINES = 500;
const MAX_LINE = 500;
const IDLE_MS = 30 * 60_000;

/**
 * Records typed command lines for the audit log. A line typed right after a password prompt is
 * stored as [REDACTED] so sudo/su passwords never reach the audit log.
 */
export function createTranscript() {
  const lines = [];
  let current = '';
  let secretNext = false;
  return {
    output(text) {
      const tail = String(text).slice(-200);
      if (/(password|passphrase)[^\n]*:\s*$/i.test(tail)) secretNext = true;
    },
    input(data) {
      for (const ch of String(data)) {
        if (ch === '\r' || ch === '\n') {
          if (lines.length < MAX_TRANSCRIPT_LINES) lines.push(secretNext ? '[REDACTED]' : current.slice(0, MAX_LINE));
          current = '';
          secretNext = false;
        } else if (ch === '\u007f' || ch === '\b') current = current.slice(0, -1);
        else if (ch >= ' ') current += ch;
      }
    },
    lines: () => lines.slice(),
  };
}

/**
 * Attaches the terminal WebSocket to the HTTP server. Flow: the browser gets a one-time ticket from
 * POST /servers/:id/terminal/ticket (Owner + MFA), then opens ws(s)://host/api/v1/servers/terminal?ticket=...
 * Client messages are JSON: {t:'in', d:'...'} for keystrokes, {t:'resize', cols, rows}. Server sends raw output.
 */
export function attachTerminal(httpServer, service, { log = console.info } = {}) {
  const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });

  httpServer.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname !== TERMINAL_PATH) return; // not ours: leave for other handlers (none today)
    let ticket;
    try {
      ticket = service.consumeTicket(url.searchParams.get('ticket'));
    } catch {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    const cols = Math.min(Math.max(Number(url.searchParams.get('cols')) || 100, 20), 400);
    const rows = Math.min(Math.max(Number(url.searchParams.get('rows')) || 30, 5), 200);
    wss.handleUpgrade(req, socket, head, (ws) => run(ws, ticket, { cols, rows }));
  });

  async function run(ws, ticket, size) {
    const started = Date.now();
    const transcript = createTranscript();
    const meta = { serverId: ticket.serverId, actorId: ticket.actorId };
    let shell;
    try {
      shell = await service.openShell(ticket.serverId, size);
    } catch (err) {
      ws.send(`\r\n\x1b[31mCould not open the terminal: ${err.message}\x1b[0m\r\n`);
      ws.close(1011, 'ssh failed');
      await service.audit({ actorId: meta.actorId, action: 'server.terminal.open', resourceId: meta.serverId, result: 'failure', metadata: { code: err.code ?? 'SSH_FAILED' } });
      return;
    }
    await service.audit({ actorId: meta.actorId, action: 'server.terminal.open', resourceId: meta.serverId, result: 'success' });
    const { stream, client } = shell;
    let idle;
    const touch = () => {
      clearTimeout(idle);
      idle = setTimeout(() => ws.close(4000, 'idle timeout'), IDLE_MS);
    };
    touch();

    stream.on('data', (d) => {
      const text = d.toString('utf8');
      transcript.output(text);
      if (ws.readyState === ws.OPEN) ws.send(text);
    });
    stream.stderr?.on('data', (d) => ws.readyState === ws.OPEN && ws.send(d.toString('utf8')));
    stream.on('close', () => ws.close(1000, 'shell closed'));

    ws.on('message', (raw) => {
      touch();
      let msg;
      try {
        msg = JSON.parse(raw.toString('utf8'));
      } catch {
        return;
      }
      if (msg?.t === 'in' && typeof msg.d === 'string') {
        transcript.input(msg.d);
        stream.write(msg.d);
      } else if (msg?.t === 'resize') {
        const c = Math.min(Math.max(Number(msg.cols) || 100, 20), 400);
        const r = Math.min(Math.max(Number(msg.rows) || 30, 5), 200);
        stream.setWindow?.(r, c, 0, 0);
      }
    });

    let closed = false;
    ws.on('close', async () => {
      if (closed) return;
      closed = true;
      clearTimeout(idle);
      try {
        stream.end();
        client.end();
      } catch {
        /* already closed */
      }
      const lines = transcript.lines();
      await service.audit({
        actorId: meta.actorId,
        action: 'server.terminal.close',
        resourceId: meta.serverId,
        result: 'success',
        metadata: { durationSec: Math.round((Date.now() - started) / 1000), commands: lines.length, transcript: lines },
      });
      log(`[terminal] session closed for server ${meta.serverId} (${lines.length} lines)`);
    });
  }

  return wss;
}
