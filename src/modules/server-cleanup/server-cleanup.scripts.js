/** Server cleanup (TASK-048): fixed per-task scripts, allowlist and output parsers. No user input reaches a shell. */

export const CLEANUP_TASKS = Object.freeze({
  'apt-cache': { label: 'APT package cache', risk: 'low', defaultEnabled: true },
  'npm-cache': { label: 'npm cache (_cacache)', risk: 'low', defaultEnabled: true },
  'tmp-old': { label: 'Files in /tmp older than 10 days', risk: 'medium', defaultEnabled: true },
  'old-logs': { label: 'Journal and rotated logs older than 14 days', risk: 'medium', defaultEnabled: true },
  'pm2-logs': { label: 'PM2 process log files (truncate)', risk: 'medium', defaultEnabled: false },
  'old-releases': { label: 'Old release folders (keep newest 5 per releases/ directory)', risk: 'medium', defaultEnabled: true },
  'docker-prune': { label: 'Docker dangling images and build cache', risk: 'high', defaultEnabled: false },
  'ram-cache': { label: 'Drop Linux page cache (sync + drop_caches=3)', risk: 'high', defaultEnabled: false },
});

export const KEEP_RELEASES = 5;
export const LOG_RETENTION_DAYS = 14;
const TMP_AGE_DAYS = 10;

/** docker / pm2-logs / ram-cache stay opt-in unless env flags enable them. */
export function enabledTasks(env = process.env) {
  const on = (k) => ['1', 'true', 'yes'].includes(String(env[k] ?? '').toLowerCase());
  const docker = on('CLEANUP_DOCKER_PRUNE');
  const pm2 = on('CLEANUP_PM2_LOGS');
  const ram = on('CLEANUP_RAM_CACHE');
  return Object.entries(CLEANUP_TASKS).map(([key, t]) => ({
    key,
    label: t.label,
    risk: t.risk,
    enabled: key === 'docker-prune' ? docker : key === 'pm2-logs' ? pm2 : key === 'ram-cache' ? ram : true,
  }));
}

const PRELUDE = 'SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo -n"';
const RELEASE_LIST = `for R in /var/www/*/releases /srv/*/releases; do [ -d "$R" ] || continue; ls -1dt "$R"/*/ 2>/dev/null | tail -n +${KEEP_RELEASES + 1}; done`;
const LOG_FIND = `$SUDO find /var/log -xdev -type f \\( -name '*.gz' -o -name '*.[0-9]' -o -name '*.old' \\) -mtime +${LOG_RETENTION_DAYS}`;
const TMP_FIND = `$SUDO find /tmp -xdev -type f -mtime +${TMP_AGE_DAYS}`;
const NPM_CACHE = 'for D in /root/.npm/_cacache /home/*/.npm/_cacache; do [ -d "$D" ] && echo "$D"; done';

/** Host meters (read-only). Printed before task sections. */
export function hostMeterScript() {
  return [
    PRELUDE,
    "echo '##host-disk'",
    "DF=$(df -B1 / 2>/dev/null | awk 'NR==2 {print $2\" \"$4}'); echo \"disk=$DF\"",
    "echo '##host-mem'",
    "awk '/^MemTotal:/{t=$2*1024} /^MemAvailable:/{a=$2*1024} /^Cached:/{c=$2*1024} /^Buffers:/{b=$2*1024} /^Shmem:/{s=$2*1024} END {print \"mem=\" t \" \" a \" \" (c+b-s)}' /proc/meminfo 2>/dev/null",
  ].join('\n');
}

/** Read-only sizes. Output: `##key`, `bytes=N`, optional `item=<bytes> <path>` lines. */
export function previewScript(tasks) {
  const parts = [hostMeterScript()];
  for (const t of tasks) {
    if (t === 'apt-cache') parts.push(`echo '##apt-cache'; echo "bytes=$($SUDO du -sb /var/cache/apt/archives 2>/dev/null | cut -f1)"`);
    if (t === 'npm-cache') {
      parts.push(
        `echo '##npm-cache'; T=0; for D in $(${NPM_CACHE}); do S=$(du -sb "$D" 2>/dev/null | cut -f1); T=$((T + \${S:-0})); echo "item=\${S:-0} $D"; done; echo "bytes=$T"`,
      );
    }
    if (t === 'tmp-old') {
      parts.push(
        `echo '##tmp-old'; F=$(${TMP_FIND} -printf '%s\\n' 2>/dev/null | awk '{s+=$1} END {print s+0}'); echo "bytes=\${F:-0}"; ${TMP_FIND} 2>/dev/null | head -n 10 | while read -r P; do S=$(stat -c%s "$P" 2>/dev/null || echo 0); echo "item=$S $P"; done`,
      );
    }
    if (t === 'old-logs') {
      parts.push(
        `echo '##old-logs'; J=$($SUDO du -sb /var/log/journal 2>/dev/null | cut -f1); F=$(${LOG_FIND} -printf '%s\\n' 2>/dev/null | awk '{s+=$1} END {print s+0}'); echo "bytes=$(( \${J:-0} + \${F:-0} ))"; echo "item=\${J:-0} /var/log/journal (reclaimable part depends on vacuum)"; echo "item=\${F:-0} rotated logs"`,
      );
    }
    if (t === 'pm2-logs') {
      parts.push(
        `echo '##pm2-logs'; if command -v pm2 >/dev/null 2>&1; then T=0; for D in /root/.pm2/logs /home/*/.pm2/logs; do [ -d "$D" ] || continue; S=$(du -sb "$D" 2>/dev/null | cut -f1); T=$((T + \${S:-0})); echo "item=\${S:-0} $D"; done; echo "bytes=$T"; else echo "unavailable=pm2"; fi`,
      );
    }
    if (t === 'old-releases') {
      parts.push(`echo '##old-releases'; T=0; for D in $(${RELEASE_LIST}); do S=$(du -sb "$D" 2>/dev/null | cut -f1); T=$((T + \${S:-0})); echo "item=\${S:-0} $D"; done; echo "bytes=$T"`);
    }
    if (t === 'docker-prune') {
      parts.push(`echo '##docker-prune'; if command -v docker >/dev/null 2>&1; then $SUDO docker system df --format 'item={{.Type}} reclaimable={{.Reclaimable}}' 2>/dev/null; echo "bytes=0"; else echo "unavailable=docker"; fi`);
    }
    if (t === 'ram-cache') {
      parts.push(
        `echo '##ram-cache'; C=$(awk '/^Cached:/{c=$2} /^Buffers:/{b=$2} /^Shmem:/{s=$2} END {print (c+b-s)*1024}' /proc/meminfo 2>/dev/null); echo "bytes=\${C:-0}"; echo "item=\${C:-0} page cache (estimate)"`,
      );
    }
  }
  return parts.join('\n');
}

/** Destructive part. Each task prints `##key` and `status=ok|fail`. Only the allowlisted tasks passed in are emitted. */
export function applyScript(tasks) {
  const parts = [PRELUDE];
  for (const t of tasks) {
    if (t === 'apt-cache') parts.push(`echo '##apt-cache'; if $SUDO apt-get clean; then echo status=ok; else echo status=fail; fi`);
    if (t === 'npm-cache') {
      parts.push(
        `echo '##npm-cache'; ok=1; for D in $(${NPM_CACHE}); do case "$D" in /root/.npm/_cacache|/home/*/.npm/_cacache) $SUDO rm -rf -- "$D" || ok=0;; esac; done; if [ "$ok" = 1 ]; then echo status=ok; else echo status=fail; fi`,
      );
    }
    if (t === 'tmp-old') {
      parts.push(`echo '##tmp-old'; if ${TMP_FIND} -delete 2>/dev/null; then echo status=ok; else echo status=fail; fi`);
    }
    if (t === 'old-logs') {
      parts.push(`echo '##old-logs'; if $SUDO journalctl --vacuum-time=${LOG_RETENTION_DAYS}d >/dev/null 2>&1 && ${LOG_FIND} -delete 2>/dev/null; then echo status=ok; else echo status=fail; fi`);
    }
    if (t === 'pm2-logs') {
      parts.push(
        `echo '##pm2-logs'; if command -v pm2 >/dev/null 2>&1 && pm2 flush >/dev/null 2>&1; then echo status=ok; else echo status=fail; fi`,
      );
    }
    if (t === 'old-releases') {
      parts.push(`echo '##old-releases'; ok=1; for D in $(${RELEASE_LIST}); do case "$D" in /var/www/*/releases/*|/srv/*/releases/*) $SUDO rm -rf -- "$D" || ok=0;; esac; done; if [ "$ok" = 1 ]; then echo status=ok; else echo status=fail; fi`);
    }
    if (t === 'docker-prune') {
      parts.push(`echo '##docker-prune'; if command -v docker >/dev/null 2>&1 && $SUDO docker image prune -f >/dev/null 2>&1 && $SUDO docker builder prune -f >/dev/null 2>&1; then echo status=ok; else echo status=fail; fi`);
    }
    if (t === 'ram-cache') {
      parts.push(
        `echo '##ram-cache'; if sync && echo 3 | $SUDO tee /proc/sys/vm/drop_caches >/dev/null; then echo status=ok; else echo status=fail; fi`,
      );
    }
  }
  return parts.join('\n');
}

export function parseCleanupOutput(stdout) {
  const out = {};
  let cur = null;
  let host = { disk: null, memory: null };
  for (const line of String(stdout ?? '').replace(/\r/g, '').split('\n')) {
    const h = /^##([\w-]+)$/.exec(line);
    if (h) {
      if (h[1] === 'host-disk' || h[1] === 'host-mem') {
        cur = { kind: h[1] };
        continue;
      }
      cur = out[h[1]] = { bytes: null, items: [], status: null, unavailable: null };
    } else if (cur?.kind === 'host-disk') {
      const m = /^disk=(\d+)\s+(\d+)$/.exec(line);
      if (m) host.disk = { totalBytes: Number(m[1]), freeBytes: Number(m[2]) };
    } else if (cur?.kind === 'host-mem') {
      const m = /^mem=(\d+)\s+(\d+)\s+(-?\d+)$/.exec(line);
      if (m) host.memory = { totalBytes: Number(m[1]), availableBytes: Number(m[2]), cacheBytes: Math.max(0, Number(m[3])) };
    } else if (cur && !cur.kind) {
      let m;
      if ((m = /^bytes=(\d*)$/.exec(line))) cur.bytes = m[1] === '' ? 0 : Number(m[1]);
      else if ((m = /^item=(.{1,300})$/.exec(line))) cur.items.push(m[1].slice(0, 300));
      else if ((m = /^status=(ok|fail)$/.exec(line))) cur.status = m[1];
      else if ((m = /^unavailable=(\w+)$/.exec(line))) cur.unavailable = m[1];
    }
  }
  for (const v of Object.values(out)) v.items = v.items.slice(0, 20);
  out.__host = host;
  return out;
}
