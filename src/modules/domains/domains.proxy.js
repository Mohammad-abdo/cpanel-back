/**
 * TASK-047: optional Caddy reverse-proxy mode (previewable script generator) and the read-only web server probe.
 *
 * CADDY_MODE=off|on (default off). The generators are pure and strict: every value is validated against a tight pattern before it
 * is placed into a Caddyfile snippet, so no hostname, user, hash or port can add directives. The apply script is fixed text; the
 * site content travels on stdin and the hostname as a positional argument. Running it on a real server is NOT_RUN.
 */
import { AppError } from '../../common/errors/app-error.js';

const HOST = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const USER = /^[a-z0-9_-]{3,32}$/;
const BCRYPT = /^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$/;

export const isCaddyEnabled = (env = process.env) => String(env.CADDY_MODE ?? 'off').toLowerCase() === 'on';

/** Pure renderer for one reverse-proxy site. Throws AppError(422) on anything that is not a plain value. */
export function renderCaddySite({ hostname, upstreamPort, basicAuth = null, wwwRedirect = false }) {
  if (!HOST.test(String(hostname))) throw new AppError(422, 'CADDY_HOST_INVALID', 'Hostname is not valid for a Caddy site');
  if (!Number.isInteger(upstreamPort) || upstreamPort < 1 || upstreamPort > 65535) throw new AppError(422, 'CADDY_PORT_INVALID', 'Upstream port is invalid');
  const lines = [`${hostname} {`, '\tencode gzip'];
  if (basicAuth) {
    if (!USER.test(String(basicAuth.user))) throw new AppError(422, 'CADDY_AUTH_INVALID', 'Basic auth user is invalid');
    if (!BCRYPT.test(String(basicAuth.hash))) throw new AppError(422, 'CADDY_AUTH_INVALID', 'Basic auth needs a bcrypt hash');
    lines.push('\tbasic_auth {', `\t\t${basicAuth.user} ${basicAuth.hash}`, '\t}');
  }
  lines.push(`\treverse_proxy 127.0.0.1:${upstreamPort}`, '}');
  if (wwwRedirect) lines.push('', `www.${hostname} {`, `\tredir https://${hostname}{uri} permanent`, '}');
  return `${lines.join('\n')}\n`;
}

/** Local lint of a rendered snippet (the real check is `caddy validate` inside the apply script). */
export function lintCaddySite(text) {
  const errors = [];
  let depth = 0;
  for (const line of String(text).split('\n')) {
    for (const ch of line) {
      if (ch === '{') depth += 1;
      if (ch === '}') depth -= 1;
      if (depth < 0) errors.push('unbalanced braces');
    }
  }
  if (depth !== 0) errors.push('unbalanced braces');
  if (/import\s|\bexec\b|\bhandle_errors\b|\{env\./i.test(text)) errors.push('forbidden directive');
  return { ok: errors.length === 0, errors: [...new Set(errors)] };
}

/** args: HOSTNAME. stdin: the site snippet. Validates with `caddy validate` and rolls back on any failure. */
export const CADDY_APPLY_SCRIPT = `set -eu
HOST="$1"
case "$HOST" in ''|*[!a-z0-9.-]*) echo "bad host" >&2; exit 64 ;; esac
command -v caddy >/dev/null 2>&1 || { echo "caddy-missing" >&2; exit 69; }
SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo -n"
DIR="/etc/caddy/sites"
TMP="$(mktemp)"; trap 'rm -f "$TMP" "$TMP.bak" "$TMP.out"' EXIT
cat > "$TMP"
FILE="$DIR/$HOST.caddy"
HAD=0
if $SUDO test -f "$FILE"; then HAD=1; $SUDO cp "$FILE" "$TMP.bak"; fi
$SUDO mkdir -p "$DIR"
$SUDO install -m 0644 "$TMP" "$FILE"
restore() { if [ "$HAD" = "1" ]; then $SUDO install -m 0644 "$TMP.bak" "$FILE"; else $SUDO rm -f "$FILE"; fi; }
if ! $SUDO caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >"$TMP.out" 2>&1; then
  tail -n 5 "$TMP.out" >&2; restore; exit 71
fi
if ! $SUDO systemctl reload caddy; then restore; $SUDO systemctl reload caddy || true; exit 72; fi
echo "NT_CADDY=applied"
`;

/** Read-only probe: which web servers are installed/running and who owns ports 80 and 443. Changes nothing. */
export const DETECT_WEBSERVER_SCRIPT = `set -u
ver() { "$@" 2>&1 | head -n 1 | tr -d '\\r' | cut -c1-80; }
if command -v nginx >/dev/null 2>&1; then echo "nginx=$(ver nginx -v)"; else echo "nginx=none"; fi
if command -v apache2 >/dev/null 2>&1; then echo "apache=$(ver apache2 -v)"; elif command -v httpd >/dev/null 2>&1; then echo "apache=$(ver httpd -v)"; else echo "apache=none"; fi
if command -v caddy >/dev/null 2>&1; then echo "caddy=$(ver caddy version)"; else echo "caddy=none"; fi
for p in 80 443; do
  who="$( (ss -ltnpH "sport = :$p" 2>/dev/null || true) | sed -n 's/.*users:(("\\([^"]*\\)".*/\\1/p' | head -n 1)"
  echo "port$p=\${who:-none}"
done
`;

export function parseWebserverProbe(stdout) {
  const out = { nginx: null, apache: null, caddy: null, port80: null, port443: null };
  for (const line of String(stdout).split('\n')) {
    const m = /^(nginx|apache|caddy|port80|port443)=(.{0,80})$/.exec(line.trim());
    if (m) out[m[1]] = m[2] === 'none' ? null : m[2];
  }
  const listener = out.port80 ?? out.port443 ?? '';
  const recommended = /caddy/i.test(listener) ? 'caddy' : /nginx/i.test(listener) ? 'nginx' : /apache|httpd/i.test(listener) ? 'apache' : out.nginx ? 'nginx' : out.apache ? 'apache' : null;
  return { ...out, recommended };
}
