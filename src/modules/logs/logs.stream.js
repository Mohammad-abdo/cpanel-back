/**
 * Live-stream session with a bounded queue (backpressure). When a slow consumer falls behind the oldest
 * queued events are dropped and the consumer is told how many were lost, so it can re-query by seq.
 * Transport is SSE (no new dependency); Socket.IO is REQUIRES DECISION.
 */
export function createStreamSession({ send, maxQueue = 200 }) {
  const queue = [];
  let dropped = 0;
  let paused = false;
  let closed = false;

  function flush() {
    while (!closed && !paused && (queue.length > 0 || dropped > 0)) {
      if (dropped > 0) {
        const n = dropped;
        dropped = 0;
        if (send({ event: 'dropped', data: { dropped: n } }) === false) paused = true;
        continue;
      }
      const item = queue.shift();
      if (send({ event: 'log', id: item.seq, data: item }) === false) paused = true;
    }
  }

  return {
    push(entry) {
      if (closed) return;
      queue.push(entry);
      while (queue.length > maxQueue) {
        queue.shift();
        dropped += 1;
      }
      flush();
    },
    /** Call when the underlying socket emits 'drain'. */
    resume() {
      paused = false;
      flush();
    },
    close() {
      closed = true;
      queue.length = 0;
    },
    get pending() {
      return queue.length;
    },
  };
}
