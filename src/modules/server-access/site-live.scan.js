/**
 * Live site inspection over SSH (read-only). Script args: $1=path $2=name $3=slug.
 * Never interpolates unsanitized user input into the script body.
 */

export const SITE_LIVE_SCRIPT = `
SITE="$1"
NAME="$2"
SLUG="$3"
# Non-interactive SSH often lacks nvm/npm PATH — load common locations.
export PATH="/usr/local/bin:/usr/bin:$HOME/.local/bin:$PATH"
if [ -s "$HOME/.nvm/nvm.sh" ]; then . "$HOME/.nvm/nvm.sh" >/dev/null 2>&1; fi
if [ -d "$HOME/.nvm/versions/node" ]; then
  _nv=$(ls -1d "$HOME/.nvm/versions/node"/v* 2>/dev/null | tail -n 1)
  [ -n "$_nv" ] && PATH="$_nv/bin:$PATH"
fi
for _p in /root/.nvm/versions/node/*/bin /home/*/.nvm/versions/node/*/bin /usr/lib/node_modules/pm2/bin; do
  [ -x "$_p/pm2" ] && PATH="$_p:$PATH"
done
PM2_BIN=$(command -v pm2 2>/dev/null || true)
pm2_jlist() {
  [ -n "$PM2_BIN" ] || return 1
  # Prefer the daemon that actually has apps (often root or a deploy user).
  for home in "$PM2_HOME" "$HOME/.pm2" /root/.pm2 /home/*/.pm2; do
    [ -n "$home" ] || continue
    [ -d "$home" ] || continue
    out=$(PM2_HOME="$home" "$PM2_BIN" jlist 2>/dev/null | head -c 700000)
    case "$out" in
      \\[*) echo "$out"; return 0 ;;
    esac
  done
  if command -v sudo >/dev/null 2>&1; then
    out=$(sudo -n "$PM2_BIN" jlist 2>/dev/null | head -c 700000)
    case "$out" in
      \\[*) echo "$out"; return 0 ;;
    esac
  fi
  PM2_HOME= "$PM2_BIN" jlist 2>/dev/null | head -c 700000
}
echo '##meta'
printf '%s\\n' "$SITE"
date -u +%Y-%m-%dT%H:%M:%SZ
printf 'pm2=%s\\n' "\${PM2_BIN:-missing}"
echo '##pm2'
pm2_jlist || true
echo '##pm2logs'
if [ -n "$PM2_BIN" ]; then
  matched=""
  BASE=$(basename "$SITE")
  for n in "$NAME" "$SLUG" "$BASE"; do
    [ -n "$n" ] || continue
    if "$PM2_BIN" describe "$n" >/dev/null 2>&1; then
      matched="$n"
      break
    fi
    for home in /root/.pm2 "$HOME/.pm2" /home/*/.pm2; do
      [ -d "$home" ] || continue
      if PM2_HOME="$home" "$PM2_BIN" describe "$n" >/dev/null 2>&1; then
        matched="$n"
        export PM2_HOME="$home"
        break 2
      fi
    done
  done
  if [ -n "$matched" ]; then
    echo "NAME:$matched"
    "$PM2_BIN" logs "$matched" --nostream --lines 80 2>/dev/null | tail -n 120
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
  const baseHost = base.includes('.') ? base.split('.')[0] : base;
  const out = [];
  for (const proc of list) {
    const row = normalizePm2(proc);
    const { cwd, name: pname, script } = row;
    const underPath =
      path &&
      (cwd === path ||
        cwd.startsWith(`${path}/`) ||
        script.startsWith(`${path}/`) ||
        (cwd && path.startsWith(`${cwd}/`)));
    const hit =
      underPath ||
      (name && pname === name) ||
      (slug && pname === slug) ||
      (base && pname === base) ||
      (baseHost && baseHost.length >= 3 && pname === baseHost) ||
      (name && name.length >= 5 && (pname.startsWith(name) || name.startsWith(pname))) ||
      (base && cwd && (cwd.endsWith(`/${base}`) || cwd.includes(`/${base}/`)));
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
  let pm2Total = 0;
  let pm2Names = [];
  let pm2RawLen = 0;
  try {
    let raw = (sec.pm2 ?? []).join('\n').trim();
    pm2RawLen = raw.length;
    if (raw.startsWith('[')) {
      let list;
      try {
        list = JSON.parse(raw);
      } catch {
        // Truncated jlist — keep complete objects only.
        const cut = raw.lastIndexOf('},');
        if (cut > 0) {
          list = JSON.parse(`${raw.slice(0, cut + 1)}]`);
        } else {
          throw new Error('pm2-json');
        }
      }
      pm2Total = Array.isArray(list) ? list.length : 0;
      pm2Names = (Array.isArray(list) ? list : [])
        .slice(0, 40)
        .map((p) => p?.name || p?.pm2_env?.name || '')
        .filter(Boolean);
      processes = matchPm2(list, { path, name, slug });
      // If path/name did not match but PM2 is present, surface online apps whose cwd shares the site folder name.
      if (!processes.length && path) {
        const base = path.replace(/\/+$/, '').split('/').pop();
        processes = matchPm2(list, { path: '', name: base, slug: base });
      }
    }
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
  const pm2BinLine = (sec.meta ?? []).map((l) => l.trim()).find((l) => l.startsWith('pm2='));
  return {
    path: sec.meta?.[0]?.trim() || path || null,
    collectedAt: sec.meta?.[1]?.trim() || new Date().toISOString(),
    pm2Bin: pm2BinLine ? pm2BinLine.slice(4) : null,
    processes,
    running: processes.some((p) => p.status === 'online'),
    pm2Total,
    pm2Names,
    pm2RawLen,
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
