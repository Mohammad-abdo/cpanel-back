/**
 * Live PM2 list/control over SSH.
 * Process names are validated before use as a single argv — never interpolated raw into bash.
 */

export const SAFE_PM2_NAME = /^[A-Za-z0-9._:-]{1,100}$/;
export const PM2_ACTIONS = Object.freeze(['start', 'stop', 'restart', 'reload', 'delete', 'logs', 'describe']);

/** Shared PATH / PM2_HOME discovery for non-interactive SSH sessions. */
export const PM2_ENV_SETUP = `
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
pm2_pick_home() {
  [ -n "$PM2_BIN" ] || return 1
  for home in "$PM2_HOME" "$HOME/.pm2" /root/.pm2 /home/*/.pm2; do
    [ -n "$home" ] || continue
    [ -d "$home" ] || continue
    out=$(PM2_HOME="$home" "$PM2_BIN" jlist 2>/dev/null | head -c 200)
    case "$out" in
      \\[*) export PM2_HOME="$home"; return 0 ;;
    esac
  done
  if command -v sudo >/dev/null 2>&1; then
    out=$(sudo -n env PM2_HOME=/root/.pm2 "$PM2_BIN" jlist 2>/dev/null | head -c 200)
    case "$out" in
      \\[*) export PM2_HOME=/root/.pm2; PM2_SUDO=1; return 0 ;;
    esac
  fi
  return 0
}
pm2_exec() {
  [ -n "$PM2_BIN" ] || return 127
  pm2_pick_home
  if [ "\${PM2_SUDO:-0}" = "1" ]; then
    sudo -n env PM2_HOME="\${PM2_HOME:-/root/.pm2}" "$PM2_BIN" "$@"
  else
    "$PM2_BIN" "$@"
  fi
}
`.trim();

export function pm2ListScript() {
  return `
${PM2_ENV_SETUP}
echo '##meta'
date -u +%Y-%m-%dT%H:%M:%SZ
printf 'pm2=%s\\n' "\${PM2_BIN:-missing}"
printf 'home=%s\\n' "\${PM2_HOME:-}"
echo '##pm2'
if [ -z "$PM2_BIN" ]; then
  echo '[]'
  exit 0
fi
pm2_pick_home
if [ "\${PM2_SUDO:-0}" = "1" ]; then
  sudo -n env PM2_HOME="\${PM2_HOME:-/root/.pm2}" "$PM2_BIN" jlist 2>/dev/null | head -c 900000
else
  PM2_HOME="\${PM2_HOME:-}" "$PM2_BIN" jlist 2>/dev/null | head -c 900000
fi
echo
`.trim();
}

/** Action script: $1 = process name. logs/describe print to stdout. */
export function pm2ActionScript(action) {
  if (!PM2_ACTIONS.includes(action)) throw Object.assign(new Error('Invalid PM2 action'), { code: 'PM2_ACTION_INVALID' });
  if (action === 'logs') {
    return `
${PM2_ENV_SETUP}
NAME="$1"
echo '##meta'
date -u +%Y-%m-%dT%H:%M:%SZ
echo '##out'
pm2_exec logs "$NAME" --nostream --lines 100 2>&1 | tail -n 160
`.trim();
  }
  if (action === 'describe') {
    return `
${PM2_ENV_SETUP}
NAME="$1"
echo '##meta'
date -u +%Y-%m-%dT%H:%M:%SZ
echo '##out'
pm2_exec describe "$NAME" 2>&1 | head -n 120
`.trim();
  }
  return `
${PM2_ENV_SETUP}
NAME="$1"
echo '##meta'
date -u +%Y-%m-%dT%H:%M:%SZ
echo '##out'
pm2_exec ${action} "$NAME" 2>&1
EC=$?
echo
echo "EXIT:$EC"
exit 0
`.trim();
}

export function assertSafePm2Name(name) {
  if (typeof name !== 'string' || !SAFE_PM2_NAME.test(name)) {
    throw Object.assign(new Error('Invalid PM2 process name'), { code: 'PM2_NAME_INVALID' });
  }
  return name;
}

export function normalizePm2Process(proc) {
  const cwd = proc?.pm2_env?.pm_cwd || proc?.pm2_env?.cwd || '';
  const pname = proc?.name || proc?.pm2_env?.name || '';
  const script = proc?.pm2_env?.pm_exec_path || '';
  const uptime = proc?.pm2_env?.pm_uptime ?? null;
  return {
    id: proc?.pm_id ?? proc?.pm2_env?.pm_id ?? null,
    name: pname,
    status: proc?.pm2_env?.status || proc?.status || 'unknown',
    pid: proc?.pid ?? null,
    cpu: proc?.monit?.cpu ?? null,
    memory: proc?.monit?.memory ?? null,
    cwd,
    script,
    restarts: proc?.pm2_env?.restart_time ?? null,
    uptime,
    uptimeMs: uptime ? Math.max(0, Date.now() - Number(uptime)) : null,
    execMode: proc?.pm2_env?.exec_mode ?? null,
    instances: proc?.pm2_env?.instances ?? null,
    unstableRestarts: proc?.pm2_env?.unstable_restarts ?? null,
    nodeVersion: proc?.pm2_env?.node_version ?? null,
  };
}

export function parsePm2List(text) {
  const sec = {};
  let cur = null;
  for (const line of String(text ?? '').split('\n')) {
    const m = /^##(\w+)$/.exec(line.trim());
    if (m) {
      cur = m[1];
      sec[cur] = [];
    } else if (cur) sec[cur].push(line);
  }
  const meta = (sec.meta ?? []).map((l) => l.trim()).filter(Boolean);
  let raw = (sec.pm2 ?? []).join('\n').trim();
  let list = [];
  if (raw.startsWith('[')) {
    try {
      list = JSON.parse(raw);
    } catch {
      const cut = raw.lastIndexOf('},');
      if (cut > 0) list = JSON.parse(`${raw.slice(0, cut + 1)}]`);
    }
  }
  const processes = (Array.isArray(list) ? list : []).map(normalizePm2Process).filter((p) => p.name);
  return {
    collectedAt: meta.find((l) => /^\d{4}-/.test(l)) || new Date().toISOString(),
    pm2Bin: (meta.find((l) => l.startsWith('pm2=')) || 'pm2=').slice(4) || null,
    pm2Home: (meta.find((l) => l.startsWith('home=')) || 'home=').slice(5) || null,
    processes,
    online: processes.filter((p) => p.status === 'online').length,
    total: processes.length,
  };
}

export function parsePm2ActionOutput(text) {
  const sec = {};
  let cur = null;
  for (const line of String(text ?? '').split('\n')) {
    const m = /^##(\w+)$/.exec(line.trim());
    if (m) {
      cur = m[1];
      sec[cur] = [];
    } else if (cur) sec[cur].push(line);
  }
  const out = (sec.out ?? []).join('\n');
  const exitLine = [...(sec.out ?? [])].reverse().find((l) => /^EXIT:\d+$/.test(l.trim()));
  const exitCode = exitLine ? Number(exitLine.replace('EXIT:', '')) : null;
  const cleaned = out.replace(/\nEXIT:\d+\s*$/, '').trim();
  return {
    collectedAt: (sec.meta ?? []).map((l) => l.trim()).find((l) => /^\d{4}-/.test(l)) || new Date().toISOString(),
    output: cleaned.slice(0, 12000),
    exitCode,
  };
}
