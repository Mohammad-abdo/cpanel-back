/**
 * Live site inspection over SSH (read-only). Script args: $1=path $2=name $3=slug.
 * Never interpolates unsanitized user input into the script body.
 */

export const SITE_LIVE_SCRIPT = `
SITE="$1"
NAME="$2"
SLUG="$3"
echo '##meta'
printf '%s\\n' "$SITE"
date -u +%Y-%m-%dT%H:%M:%SZ
echo '##pm2'
if command -v pm2 >/dev/null 2>&1; then pm2 jlist 2>/dev/null | head -c 200000; fi
echo '##pm2logs'
if command -v pm2 >/dev/null 2>&1; then
  matched=""
  for n in "$NAME" "$SLUG"; do
    [ -n "$n" ] || continue
    if pm2 describe "$n" >/dev/null 2>&1; then
      matched="$n"
      break
    fi
  done
  if [ -n "$matched" ]; then
    echo "NAME:$matched"
    pm2 logs "$matched" --nostream --lines 80 2>/dev/null | tail -n 120
  fi
fi
echo '##applog'
for f in \\
  "$SITE/storage/logs/laravel.log" \\
  "$SITE/storage/logs/$(date -u +%Y-%m-%d).log" \\
  "$SITE/logs/error.log" \\
  "$SITE/log/error.log" \\
  "$SITE/error.log" \\
  "$SITE/app.log"; do
  if [ -f "$f" ]; then
    echo "FILE:$f"
    tail -n 80 "$f" 2>/dev/null
    break
  fi
done
found=$(find "$SITE" -maxdepth 3 -type f \\( -name '*.log' -o -name 'error_log' \\) ! -path '*/node_modules/*' 2>/dev/null | head -n 5)
for f in $found; do
  [ -f "$f" ] || continue
  echo "FILE:$f"
  tail -n 40 "$f" 2>/dev/null
done
echo '##files'
ls -la "$SITE" 2>/dev/null | head -n 50
echo '##git'
if [ -d "$SITE/.git" ]; then
  git -C "$SITE" rev-parse --abbrev-ref HEAD 2>/dev/null
  git -C "$SITE" log -1 --pretty=format:'%h %s' 2>/dev/null
  echo
  git -C "$SITE" remote get-url origin 2>/dev/null || true
fi
`.trim();

function sections(text) {
  const sec = {};
  let cur = null;
  for (const line of String(text ?? '').split('\n')) {
    const m = /^##(\w+)$/.exec(line.trim());
    if (m) {
      cur = m[1];
      sec[cur] = [];
    } else if (cur) sec[cur].push(line);
  }
  return sec;
}

function normalizePm2(proc) {
  const cwd = proc?.pm2_env?.pm_cwd || proc?.pm2_env?.cwd || '';
  const pname = proc?.name || proc?.pm2_env?.name || '';
  const script = proc?.pm2_env?.pm_exec_path || '';
  return {
    name: pname,
    status: proc?.pm2_env?.status || proc?.status || 'unknown',
    pid: proc?.pid ?? null,
    cpu: proc?.monit?.cpu ?? null,
    memory: proc?.monit?.memory ?? null,
    cwd,
    script,
    restarts: proc?.pm2_env?.restart_time ?? null,
    uptime: proc?.pm2_env?.pm_uptime ?? null,
    execMode: proc?.pm2_env?.exec_mode ?? null,
    instances: proc?.pm2_env?.instances ?? null,
  };
}

function matchPm2(list, { path, name, slug }) {
  const base = path ? path.replace(/\/+$/, '').split('/').pop() : '';
  const out = [];
  for (const proc of list) {
    const row = normalizePm2(proc);
    const { cwd, name: pname, script } = row;
    const hit =
      (path && (cwd === path || cwd.startsWith(`${path}/`) || script.startsWith(`${path}/`))) ||
      (name && (pname === name || pname.includes(name))) ||
      (slug && (pname === slug || pname.includes(slug))) ||
      (base && (pname === base || pname.includes(base) || cwd.includes(`/${base}`) || script.includes(`/${base}/`)));
    if (!hit) continue;
    const { script: _s, ...rest } = row;
    out.push(rest);
  }
  return out;
}

/** Parse SITE_LIVE_SCRIPT stdout. */
export function parseSiteLive(text, { path, name, slug } = {}) {
  const sec = sections(text);
  let processes = [];
  try {
    const raw = (sec.pm2 ?? []).join('').trim();
    if (raw.startsWith('[')) processes = matchPm2(JSON.parse(raw), { path, name, slug });
  } catch {
    processes = [];
  }

  const logLines = [];
  let logSource = null;
  for (const line of [...(sec.pm2logs ?? []), ...(sec.applog ?? [])]) {
    if (line.startsWith('NAME:') || line.startsWith('FILE:')) {
      logSource = line.replace(/^(NAME|FILE):/, '').trim();
      continue;
    }
    if (line.trim()) logLines.push(line);
  }

  const git = (sec.git ?? []).map((l) => l.trim()).filter(Boolean);
  return {
    path: sec.meta?.[0]?.trim() || path || null,
    collectedAt: sec.meta?.[1]?.trim() || new Date().toISOString(),
    processes,
    running: processes.some((p) => p.status === 'online'),
    logs: {
      source: logSource,
      lines: logLines.slice(-120),
    },
    files: (sec.files ?? []).map((l) => l.trimEnd()).filter(Boolean).slice(0, 50),
    git: {
      branch: git[0] || null,
      head: git[1] || null,
      remote: git[2] || null,
    },
  };
}

export function assertSafeSitePath(path) {
  if (typeof path !== 'string' || !path.startsWith('/') || path.includes('\0') || path.includes('..')) {
    return false;
  }
  return /^\/[A-Za-z0-9._/+\-]+$/.test(path);
}
