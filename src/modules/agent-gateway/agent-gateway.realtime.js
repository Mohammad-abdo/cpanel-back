/**
 * Process-wide realtime publisher. A no-op until the Socket.IO hub attaches (or when socket.io is absent),
 * so services can call publish() unconditionally and the web falls back to polling.
 */
let publisher = null;
export const realtime = {
  attach(fn) {
    publisher = fn;
  },
  publish(room, event, payload) {
    try {
      publisher?.(room, event, payload);
    } catch {
      /* realtime is best effort */
    }
  },
  get active() {
    return publisher !== null;
  },
};
