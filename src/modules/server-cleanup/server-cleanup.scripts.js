/** Server cleanup (TASK-048): fixed per-task scripts, allowlist and output parsers. No user input reaches a shell. */

export const CLEANUP_TASKS = Object.freeze({
  'apt-cache': { label: 'APT package cache', risk: 'low', defaultEnabled: true },
  'old-logs': { label: 'Journal and rotated logs older than 14 days', risk: 'medium', defaultEnabled: true },
  'old-releases': { label: 'Old release folders (keep newest 5 per releases/ directory)', risk: 'medium', defaultEnabled: true },
  'docker-prune': { label: 'Docker dangling images and build cache', risk: 'high', defaultEnabled: false },
});

export const KEEP_RELEASES = 5;
export const LOG_RETENTION_DAYS = 14;

/** docker prune is off unless the operator enables it explicitly (CLEANUP_DOCKER_PRUNE=true). */
export function enabledTasks(env = process.env) {
  const docker = ['1', 'true', 'yes'].includes(String(env.CLEANUP_DOCKER_PRUNE ?? '').toLowerCase());
  return Object.entries(CLEANUP_TASKS).map(([key, t]) => ({ key, label: t.label, risk: t.risk, enabled: key === 'docker-prune' ? docker : true }));
}

const PRELUDE = 'SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo -n"';
const RELEASE_LIST = `for R in /var/www/*/releases /srv/*/releases; do [ -d "$R" ] || continue; ls -1dt "$R"/*/ 2>/dev/null | tail -n +${KEEP_RELEASES + 1}; done`;
const LOG_FIND = `$SUDO find /var/log -xdev -type f \\( -name '*.gz' -o -name '*.[0-9]' -o -name '*.old' \\) -mtime +${LOG_RETENTION_DAYS}`;

/** Read-only sizes. Output: `##key`, `bytes=N`, optional `item=<bytes> <path>` lines. */
export function previewScript(tasks) {
  const parts = [PRELUDE];
  for (const t of tasks) {
    if (t === 'apt-cache') parts.push(`echo '##apt-cache'; echo "bytes=$($SUDO du -sb /var/cache/apt/archives 2>/dev/null | cut -f1)"`);
    if (t === 'old-logs') {
      parts.push(
        `echo '##old-logs'; J=$($SUDO du -sb /var/log/journal 2>/dev/null | cut -f1); F=$(${LOG_FIND} -printf '%s\\n' 2>/dev/null | awk '{s+=$1} END {print s+0}'); echo "bytes=$(( \${J:-0} + \${F:-0} ))"; echo "item=\${J:-0} /var/log/journal (reclaimable part depends on vacuum)"; echo "item=\${F:-0} rotated logs"`,
      );
    }
    if (t === 'old-releases') {
      parts.push(`echo '##old-releases'; T=0; for D in $(${RELEASE_LIST}); do S=$(du -sb "$D" 2>/dev/null | cut -f1); T=$((T + \${S:-0})); echo "item=\${S:-0} $D"; done; echo "bytes=$T"`);
    }
    if (t === 'docker-prune') {
      parts.push(`echo '##docker-prune'; if command -v docker >/dev/null 2>&1; then $SUDO docker system df --format 'item={{.Type}} reclaimable={{.Reclaimable}}' 2>/dev/null; echo "bytes=0"; else echo "unavailable=docker"; fi`);
    }
  }
  return parts.join('\n');
}

/** Destructive part. Each task prints `##key` and `status=ok|fail`. Only the allowlisted tasks passed in are emitted. */
export function applyScript(tasks) {
  const parts = [PRELUDE];
  for (const t of tasks) {
    if (t === 'apt-cache') parts.push(`echo '##apt-cache'; if $SUDO apt-get clean; then echo status=ok; else echo status=fail; fi`);
    if (t === 'old-logs') {
      parts.push(`echo '##old-logs'; if $SUDO journalctl --vacuum-time=${LOG_RETENTION_DAYS}d >/dev/null 2>&1 && ${LOG_FIND} -delete 2>/dev/null; then echo status=ok; else echo status=fail; fi`);
    }
    if (t === 'old-releases') {
      parts.push(`echo '##old-releases'; ok=1; for D in $(${RELEASE_LIST}); do case "$D" in /var/www/*/releases/*|/srv/*/releases/*) $SUDO rm -rf -- "$D" || ok=0;; esac; done; if [ "$ok" = 1 ]; then echo status=ok; else echo status=fail; fi`);
    }
    if (t === 'docker-prune') {
      parts.push(`echo '##docker-prune'; if command -v docker >/dev/null 2>&1 && $SUDO docker image prune -f >/dev/null 2>&1 && $SUDO docker builder prune -f >/dev/null 2>&1; then echo status=ok; else echo status=fail; fi`);
    }
  }
  return parts.join('\n');
}

export function parseCleanupOutput(stdout) {
  const out = {};
  let cur = null;
  for (const line of String(stdout ?? '').replace(/\r/g, '').split('\n')) {
    const h = /^##([\w-]+)$/.exec(line);
    if (h) {
      cur = out[h[1]] = { bytes: null, items: [], status: null, unavailable: null };
    } else if (cur) {
      let m;
      if ((m = /^bytes=(\d*)$/.exec(line))) cur.bytes = m[1] === '' ? 0 : Number(m[1]);
      else if ((m = /^item=(.{1,300})$/.exec(line))) cur.items.push(m[1].slice(0, 300));
      else if ((m = /^status=(ok|fail)$/.exec(line))) cur.status = m[1];
      else if ((m = /^unavailable=(\w+)$/.exec(line))) cur.unavailable = m[1];
    }
  }
  for (const v of Object.values(out)) v.items = v.items.slice(0, 20);
  return out;
}
