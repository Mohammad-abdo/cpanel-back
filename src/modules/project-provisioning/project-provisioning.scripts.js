/**
 * TASK-053: fixed remote scripts and pure renderers for "Add project to server" (Apache + certbot + PM2, Debian/Ubuntu layout).
 *
 * Rules: scripts are constant text. Variable input arrives only as positional arguments ("$1", ...) through execScriptStdin and
 * is validated before it gets here; secrets (git token, deploy key, env file) arrive only on stdin. Renderers (Apache vhost,
 * PM2 ecosystem) only interpolate values that passed the strict validators and re-check them defensively.
 * Running any of this on a real server is NOT_RUN (PROVISION_EXECUTOR=simulated by default).
 */
import { AppError } from '../../common/errors/app-error.js';
import { ALLOWED_COMMANDS, SAFE_REL_PATH } from '../deployments/deployments.commands.js';
import { PM2_ENV_SETUP } from '../server-access/pm2-live.scan.js';
import { HOSTNAME, validateAppRoot, validatePort, validateSlug } from './project-provisioning.validator.js';

const SUDO = 'SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo -n"';
const REQUIRED_MODS = ['proxy_module', 'proxy_http_module', 'proxy_wstunnel_module', 'rewrite_module', 'headers_module', 'ssl_module'];
const DOC_ROOT = /^\/(?:srv|var\/www|opt)\/[A-Za-z0-9._/-]{1,200}$/;

function assertHost(h) {
  if (!HOSTNAME.test(String(h))) throw new AppError(422, 'DOMAIN_INVALID', 'Domain must be a plain hostname such as app.example.com');
  return h;
}
export const appDirFor = (appRoot, slug) => `${validateAppRoot(appRoot)}/${validateSlug(slug)}`;
export const vhostConfName = (primary) => `nt-${assertHost(primary)}.conf`;
export const pm2NameFor = (slug) => `nt-${validateSlug(slug)}`;

// ---------------------------------------------------------------------------------------------------- renderers

/** Apache virtual host text. proxy: ProxyPass to 127.0.0.1:<port> with WebSocket upgrade. static: DocumentRoot + FallbackResource. */
export function renderApacheVhost({ domains, port = null, docRoot = null, tls = false }) {
  const names = (domains ?? []).map(assertHost);
  if (!names.length) throw new AppError(422, 'DOMAIN_INVALID', 'At least one domain is required');
  const [primary, ...aliases] = names;
  const proxy = docRoot == null;
  if (proxy) validatePort(port);
  else if (!DOC_ROOT.test(docRoot) || docRoot.includes('..')) throw new AppError(422, 'DOC_ROOT_INVALID', 'Static document root is not allowed');
  const alias = aliases.length ? [`  ServerAlias ${aliases.join(' ')}`] : [];
  const head = (scheme) => [
    `  ServerName ${primary}`,
    ...alias,
    `  ErrorLog \${APACHE_LOG_DIR}/${primary}-error.log`,
    `  CustomLog \${APACHE_LOG_DIR}/${primary}-access.log combined`,
    '  Header always set X-Content-Type-Options "nosniff"',
    '  Header always set X-Frame-Options "SAMEORIGIN"',
    '  Header always set Referrer-Policy "strict-origin-when-cross-origin"',
    '  Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"',
    ...(scheme === 'https' ? ['  Header always set Strict-Transport-Security "max-age=31536000"'] : []),
  ];
  const body = (scheme) =>
    proxy
      ? [
          '  ProxyPreserveHost On',
          `  RequestHeader set X-Forwarded-Proto "${scheme}"`,
          '  RewriteEngine On',
          '  RewriteCond %{HTTP:Upgrade} =websocket [NC]',
          `  RewriteRule /(.*) ws://127.0.0.1:${port}/$1 [P,L]`,
          `  ProxyPass / http://127.0.0.1:${port}/`,
          `  ProxyPassReverse / http://127.0.0.1:${port}/`,
        ]
      : [
          `  DocumentRoot ${docRoot}`,
          `  <Directory ${docRoot}>`,
          '    Options -Indexes +FollowSymLinks',
          '    AllowOverride None',
          '    Require all granted',
          '    FallbackResource /index.html',
          '  </Directory>',
        ];
  if (!tls) return ['<VirtualHost *:80>', ...head('http'), ...body('http'), '</VirtualHost>', ''].join('\n');
  return [
    '<VirtualHost *:80>',
    `  ServerName ${primary}`,
    ...alias,
    '  RewriteEngine On',
    '  RewriteCond %{HTTPS} off',
    '  RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]',
    '</VirtualHost>',
    '',
    '<VirtualHost *:443>',
    ...head('https'),
    '  SSLEngine on',
    `  SSLCertificateFile /etc/letsencrypt/live/${primary}/fullchain.pem`,
    `  SSLCertificateKeyFile /etc/letsencrypt/live/${primary}/privkey.pem`,
    '  Include /etc/letsencrypt/options-ssl-apache.conf',
    ...body('https'),
    '</VirtualHost>',
    '',
  ].join('\n');
}

/** PM2 ecosystem file. Holds no secrets: variables are read at start from <appDir>/app/.env (0600). */
export function renderEcosystem({ name, appDir, port, mode = 'npm-start', startFile = null }) {
  validatePort(port);
  if (!/^nt-[a-z0-9-]{1,40}$/.test(name)) throw new AppError(422, 'PM2_APP_INVALID', 'pm2 app name is invalid');
  if (mode === 'file' && !(startFile && SAFE_REL_PATH.test(startFile))) throw new AppError(422, 'START_FILE_INVALID', 'Start file is invalid');
  if (!DOC_ROOT.test(appDir) || appDir.includes('..')) throw new AppError(422, 'DEPLOY_PATH_INVALID', 'App directory is not allowed');
  const script = mode === 'file' ? { script: startFile } : { script: 'npm', args: 'start' };
  return `// Generated by NodeTeam (TASK-053). No secrets here: variables come from app/.env (0600).
const fs = require('fs');
const path = require('path');
const fileEnv = {};
try {
  for (const line of fs.readFileSync(path.join(__dirname, 'app', '.env'), 'utf8').split('\\n')) {
    const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (!m) continue;
    try { fileEnv[m[1]] = JSON.parse(m[2]); } catch { fileEnv[m[1]] = m[2]; }
  }
} catch {}
module.exports = {
  apps: [{
    name: ${JSON.stringify(name)},
    cwd: ${JSON.stringify(`${appDir}/app`)},
    script: ${JSON.stringify(script.script)},${script.args ? `\n    args: ${JSON.stringify(script.args)},` : ''}
    env: { ...fileEnv, NODE_ENV: 'production', PORT: ${JSON.stringify(String(port))} },
    autorestart: true,
    max_restarts: 10,
  }],
};
`;
}

/** .env text: KEY="json-escaped value". The values never appear in args, logs or the stored plan. */
export function renderEnvFile(vars) {
  const lines = (vars ?? []).map(({ key, value }) => {
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,99}$/.test(key) || /[\0\r\n]/.test(value)) throw new AppError(422, 'ENV_VAR_INVALID', 'Environment variable is invalid');
    return `${key}=${JSON.stringify(value)}`;
  });
  return `${lines.join('\n')}\n`;
}

// ---------------------------------------------------------------------------------------------------- scripts

/** args: PORT_START PORT_END WANTED_PORT(0=auto) APP_ROOT. Prints NT_* key=value lines; never mutates the server. */
export const PREFLIGHT_SCRIPT = `${PM2_ENV_SETUP}
set -u
PSTART="$1"; PEND="$2"; WANT="$3"; ROOT="$4"
case "$PSTART$PEND$WANT" in ''|*[!0-9]*) echo "bad port args" >&2; exit 64 ;; esac
. /etc/os-release 2>/dev/null; echo "NT_OS=\${PRETTY_NAME:-unknown}"
if command -v apache2 >/dev/null 2>&1; then echo NT_APACHE=apache2; CTL=apache2ctl
elif command -v httpd >/dev/null 2>&1; then echo NT_APACHE=httpd; CTL=apachectl
else echo NT_APACHE=missing; CTL=""; fi
if [ -d /etc/apache2/sites-available ]; then echo NT_LAYOUT=debian; else echo NT_LAYOUT=other; fi
MODS=""
if [ -n "$CTL" ]; then MODS="$( (sudo -n $CTL -M 2>/dev/null || $CTL -M 2>/dev/null) | tr -d ' ' )"; fi
MISSING=""
for m in ${REQUIRED_MODS.join(' ')}; do case "$MODS" in *"$m"*) ;; *) MISSING="$MISSING $m" ;; esac; done
echo "NT_MODS_MISSING=\${MISSING# }"
if command -v certbot >/dev/null 2>&1; then echo "NT_CERTBOT=$(certbot --version 2>&1 | head -n 1)"; else echo NT_CERTBOT=missing; fi
if certbot plugins 2>/dev/null | grep -qi apache; then echo NT_CERTBOT_APACHE=yes; else echo NT_CERTBOT_APACHE=no; fi
echo "NT_NODE=$(node --version 2>/dev/null || echo missing)"
if [ -n "\${PM2_BIN:-}" ]; then echo "NT_PM2=$("$PM2_BIN" --version 2>/dev/null | tail -n 1)"; else echo "NT_PM2="; fi
echo "NT_GIT=$(git --version 2>/dev/null || echo missing)"
if [ "$(id -u)" -eq 0 ] || sudo -n true 2>/dev/null; then echo NT_SUDO=ok; else echo NT_SUDO=missing; fi
USED="$(ss -ltn 2>/dev/null | awk 'NR>1{n=split($4,a,":"); print a[n]}' | sort -u)"
chosen=0
if [ "$WANT" -ne 0 ]; then
  if echo "$USED" | grep -qx "$WANT"; then echo NT_PORT_BUSY=$WANT; else chosen=$WANT; fi
else
  p=$PSTART
  while [ "$p" -le "$PEND" ]; do
    if ! echo "$USED" | grep -qx "$p"; then chosen=$p; break; fi
    p=$((p+1))
  done
fi
echo "NT_PORT=$chosen"
PARENT="$ROOT"; while [ ! -d "$PARENT" ] && [ "$PARENT" != "/" ]; do PARENT="$(dirname "$PARENT")"; done
echo "NT_DISK_MB=$(df -Pm "$PARENT" 2>/dev/null | awk 'NR==2{print $4}')"
`;

/** args: APP_DIR. Creates the directory owned by the SSH login user. Idempotent. */
export const APPDIR_SCRIPT = `set -eu
APP="$1"
case "$APP" in /srv/*|/var/www/*|/opt/*) ;; *) echo "bad app dir" >&2; exit 64 ;; esac
case "$APP" in *..*|*[!A-Za-z0-9._/-]*) echo "bad app dir" >&2; exit 64 ;; esac
${SUDO}
$SUDO mkdir -p "$APP"
$SUDO chown "$(id -un):$(id -gn)" "$APP"
chmod 750 "$APP"
echo "NT_APPDIR=$APP"
`;

/**
 * args: APP_DIR REPO_URL BRANCH SHA('-' = branch head) AUTH(none|token|key). stdin: token or private key.
 * The secret goes to a 0600 file in a 0700 temp directory (removed on exit) and is used through GIT_ASKPASS / GIT_SSH_COMMAND only.
 */
export const CLONE_SCRIPT = `set -eu
APP="$1"; URL="$2"; BRANCH="$3"; SHA="$4"; AUTH="$5"
case "$APP" in /srv/*|/var/www/*|/opt/*) ;; *) echo "bad app dir" >&2; exit 64 ;; esac
case "$URL" in -*|'') echo "bad url" >&2; exit 64 ;; esac
case "$BRANCH" in -*|'') echo "bad branch" >&2; exit 64 ;; esac
umask 077
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export GIT_TERMINAL_PROMPT=0
case "$AUTH" in
  token)
    cat > "$TMP/secret"
    printf '#!/bin/sh\\ncase "$1" in Username*) echo x-access-token ;; *) cat "%s/secret" ;; esac\\n' "$TMP" > "$TMP/askpass"
    chmod 700 "$TMP/askpass"
    export GIT_ASKPASS="$TMP/askpass" ;;
  key)
    cat > "$TMP/key"; chmod 600 "$TMP/key"
    export GIT_SSH_COMMAND="ssh -i $TMP/key -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new" ;;
  none) : ;;
  *) echo "bad auth" >&2; exit 64 ;;
esac
mkdir -p "$APP"
cd "$APP"
if [ -d app/.git ]; then
  git -C app remote set-url origin "$URL"
  git -C app fetch --prune origin "$BRANCH" >"$TMP/out" 2>&1 || { tail -n 5 "$TMP/out" >&2; exit 70; }
else
  git clone --branch "$BRANCH" --single-branch -- "$URL" app >"$TMP/out" 2>&1 || { tail -n 5 "$TMP/out" >&2; exit 70; }
fi
if [ "$SHA" != "-" ]; then
  git -C app checkout --detach "$SHA" >"$TMP/out" 2>&1 || { tail -n 5 "$TMP/out" >&2; exit 71; }
else
  git -C app checkout -B "$BRANCH" "origin/$BRANCH" >"$TMP/out" 2>&1 || { tail -n 5 "$TMP/out" >&2; exit 71; }
fi
echo "NT_SHA=$(git -C app rev-parse HEAD)"
if [ -f app/package.json ]; then echo "NT_PKG_B64=$(head -c 30000 app/package.json | base64 -w0)"; else echo NT_PKG_B64=; fi
`;

/** args: APP_DIR. stdin: env file text. Written 0600 atomically; prints only the variable count. */
export const ENV_SCRIPT = `set -eu
APP="$1"
case "$APP" in /srv/*|/var/www/*|/opt/*) ;; *) echo "bad app dir" >&2; exit 64 ;; esac
umask 077
[ -d "$APP/app" ] || { echo "app dir missing" >&2; exit 66; }
cat > "$APP/app/.env.nt-tmp"
chmod 600 "$APP/app/.env.nt-tmp"
mv -f "$APP/app/.env.nt-tmp" "$APP/app/.env"
echo "NT_ENV_VARS=$(grep -c '=' "$APP/app/.env" || true)"
`;

/** args: APP_DIR INSTALL_ID BUILD_ID. Ids map to a fixed argv inside the script; anything else is refused. */
export const BUILD_SCRIPT = `${PM2_ENV_SETUP}
set -eu
APP="$1"; INSTALL="$2"; BUILD="$3"
case "$APP" in /srv/*|/var/www/*|/opt/*) ;; *) echo "bad app dir" >&2; exit 64 ;; esac
cd "$APP/app"
LOG="$(mktemp)"; trap 'rm -f "$LOG"' EXIT
run_id() {
  case "$1" in
${Object.entries(ALLOWED_COMMANDS).map(([id, argv]) => `    '${id}') ${argv.join(' ')} >"$LOG" 2>&1 ;;`).join('\n')}
    '-') return 0 ;;
    *) echo "command not allowed" >&2; return 64 ;;
  esac
}
run_id "$INSTALL" || { tail -n 25 "$LOG" >&2; echo "install failed" >&2; exit 70; }
echo "NT_INSTALL=$INSTALL"
export NODE_ENV=production
run_id "$BUILD" || { tail -n 25 "$LOG" >&2; echo "build failed" >&2; exit 71; }
echo "NT_BUILD=$BUILD"
tail -n 8 "$LOG" 2>/dev/null || true
`;

/** args: APP_DIR PM2_NAME PORT. stdin: ecosystem file text. Starts or reloads, saves the process list, waits for the port. */
export const PM2_SCRIPT = `${PM2_ENV_SETUP}
set -eu
APP="$1"; NAME="$2"; PORT="$3"
case "$APP" in /srv/*|/var/www/*|/opt/*) ;; *) echo "bad app dir" >&2; exit 64 ;; esac
case "$NAME" in nt-*) ;; *) echo "bad name" >&2; exit 64 ;; esac
case "$PORT" in ''|*[!0-9]*) echo "bad port" >&2; exit 64 ;; esac
[ -n "\${PM2_BIN:-}" ] || { echo "pm2-missing" >&2; exit 69; }
umask 022
cat > "$APP/ecosystem.config.cjs"
cd "$APP"
"$PM2_BIN" startOrReload ecosystem.config.cjs --update-env >/dev/null 2>&1 || { echo "pm2 start failed" >&2; exit 70; }
"$PM2_BIN" save >/dev/null 2>&1 || true
i=0
while [ "$i" -lt 30 ]; do
  if ss -ltn 2>/dev/null | awk 'NR>1{print $4}' | grep -q ":$PORT$"; then echo "NT_LISTENING=$PORT"; echo "NT_PM2_NAME=$NAME"; exit 0; fi
  i=$((i+1)); sleep 1
done
"$PM2_BIN" logs "$NAME" --lines 15 --nostream 2>&1 | tail -n 15 >&2 || true
echo "app did not listen on port $PORT" >&2
exit 72
`;

/**
 * args: CONF_NAME. stdin: vhost text. Installs into sites-available, a2ensite, runs configtest BEFORE reload and reverts
 * to the previous file (or removes the new one) if configtest fails. Prints NT_REVERTED=1 on revert.
 */
export const VHOST_SCRIPT = `set -eu
CONF="$1"
case "$CONF" in nt-*.conf) ;; *) echo "bad conf name" >&2; exit 64 ;; esac
case "$CONF" in *[!A-Za-z0-9.-]*) echo "bad conf name" >&2; exit 64 ;; esac
${SUDO}
DIR=/etc/apache2/sites-available
[ -d "$DIR" ] || { echo "apache2 sites-available missing" >&2; exit 66; }
CTL=apache2ctl; command -v apache2ctl >/dev/null 2>&1 || CTL=apachectl
umask 077
TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
cat > "$TMP"
BAK=""
if $SUDO test -f "$DIR/$CONF"; then BAK="$(mktemp)"; $SUDO cat "$DIR/$CONF" > "$BAK"; fi
$SUDO install -m 644 "$TMP" "$DIR/$CONF"
$SUDO a2ensite "$CONF" >/dev/null 2>&1 || true
if ! $SUDO $CTL configtest >"$TMP" 2>&1; then
  tail -n 6 "$TMP" >&2
  if [ -n "$BAK" ]; then $SUDO install -m 644 "$BAK" "$DIR/$CONF"; rm -f "$BAK"
  else $SUDO a2dissite "$CONF" >/dev/null 2>&1 || true; $SUDO rm -f "$DIR/$CONF"; fi
  echo "NT_REVERTED=1"
  echo "configtest failed; previous configuration restored; Apache was NOT reloaded" >&2
  exit 71
fi
[ -z "$BAK" ] || rm -f "$BAK"
$SUDO systemctl reload apache2 2>/dev/null || $SUDO $CTL graceful
echo "NT_CONF=$DIR/$CONF"
echo "NT_RELOADED=1"
`;

/** args: PRIMARY EMAIL REDIRECT(0|1) STAGING(0|1) DRYRUN(0|1) then the domain names. Output: NT_EXPIRES. */
export const CERTBOT_APACHE_SCRIPT = `set -eu
PRIMARY="$1"; EMAIL="$2"; REDIRECT="$3"; STAGING="$4"; DRY="$5"; shift 5
case "$PRIMARY" in ''|*[!a-z0-9.-]*) echo "bad domain" >&2; exit 64 ;; esac
case "$EMAIL" in ''|*[!A-Za-z0-9._%+@-]*) echo "bad email" >&2; exit 64 ;; esac
DARGS=""
for d in "$@"; do
  case "$d" in ''|*[!a-z0-9.-]*) echo "bad domain" >&2; exit 64 ;; esac
  DARGS="$DARGS -d $d"
done
command -v certbot >/dev/null 2>&1 || { echo "certbot-missing" >&2; exit 69; }
${SUDO}
umask 077
OUT="$(mktemp)"; trap 'rm -f "$OUT"' EXIT
EXTRA=""; [ "$STAGING" = "1" ] && EXTRA="--staging"
RED="--no-redirect"; [ "$REDIRECT" = "1" ] && RED="--redirect"
if ! $SUDO certbot --apache --non-interactive --agree-tos --email "$EMAIL" --cert-name "$PRIMARY" --keep-until-expiring $RED $EXTRA $DARGS >"$OUT" 2>&1; then
  tail -n 6 "$OUT" >&2; echo "certbot failed; certbot rolled back its Apache change" >&2; exit 70
fi
if [ "$DRY" = "1" ]; then
  if $SUDO certbot renew --dry-run --cert-name "$PRIMARY" >"$OUT" 2>&1; then echo NT_RENEW_DRYRUN=ok; else tail -n 4 "$OUT" >&2; echo NT_RENEW_DRYRUN=failed; fi
fi
$SUDO openssl x509 -enddate -noout -in "/etc/letsencrypt/live/$PRIMARY/cert.pem" | sed 's/^notAfter=/NT_EXPIRES=/'
`;

/** args: CONF_NAME PM2_NAME. Disables the vhost and removes the pm2 process. Files, repository and databases stay. */
export const DECOMMISSION_SCRIPT = `${PM2_ENV_SETUP}
set -eu
CONF="$1"; NAME="$2"
case "$CONF" in nt-*.conf) ;; *) echo "bad conf name" >&2; exit 64 ;; esac
case "$CONF" in *[!A-Za-z0-9.-]*) echo "bad conf name" >&2; exit 64 ;; esac
case "$NAME" in nt-*) ;; *) echo "bad name" >&2; exit 64 ;; esac
${SUDO}
CTL=apache2ctl; command -v apache2ctl >/dev/null 2>&1 || CTL=apachectl
$SUDO a2dissite "$CONF" >/dev/null 2>&1 || true
if $SUDO $CTL configtest >/dev/null 2>&1; then
  $SUDO systemctl reload apache2 2>/dev/null || $SUDO $CTL graceful
  echo NT_VHOST_DISABLED=1
else
  echo "configtest failed after disabling; Apache NOT reloaded; vhost re-enabled" >&2
  $SUDO a2ensite "$CONF" >/dev/null 2>&1 || true
  exit 71
fi
if [ -n "\${PM2_BIN:-}" ]; then
  if "$PM2_BIN" delete "$NAME" >/dev/null 2>&1; then echo NT_PM2_DELETED=1; else echo NT_PM2_DELETED=0; fi
  "$PM2_BIN" save >/dev/null 2>&1 || true
fi
`;

/** args: CONF_NAME PM2_NAME PRIMARY. Read-only: what is actually on the server. */
export const INSPECT_SCRIPT = `${PM2_ENV_SETUP}
set -u
CONF="$1"; NAME="$2"; PRIMARY="$3"
case "$CONF" in nt-*.conf) ;; *) exit 64 ;; esac
case "$CONF$PRIMARY" in *[!A-Za-z0-9.-]*) exit 64 ;; esac
${SUDO}
F="/etc/apache2/sites-available/$CONF"
if $SUDO test -f "$F"; then echo NT_VHOST_FILE=present; else echo NT_VHOST_FILE=missing; fi
if [ -e "/etc/apache2/sites-enabled/$CONF" ]; then echo NT_VHOST_ENABLED=yes; else echo NT_VHOST_ENABLED=no; fi
echo "NT_VHOST_B64=$($SUDO head -c 6000 "$F" 2>/dev/null | base64 -w0)"
if [ -n "\${PM2_BIN:-}" ]; then echo "NT_PM2_B64=$("$PM2_BIN" jlist 2>/dev/null | head -c 600000 | base64 -w0)"; else echo NT_PM2_B64=; fi
$SUDO openssl x509 -enddate -noout -in "/etc/letsencrypt/live/$PRIMARY/cert.pem" 2>/dev/null | sed 's/^notAfter=/NT_EXPIRES=/'
true
`;

/** Parses NT_KEY=value lines. */
export function parseKv(stdout) {
  const out = {};
  for (const line of String(stdout ?? '').split('\n')) {
    const m = /^NT_([A-Z0-9_]+)=(.*)$/.exec(line.trim());
    if (m) out[m[1]] = m[2];
  }
  return out;
}

/** Turns parsed preflight output into blockers (must fix) and warnings. */
export function evaluatePreflight(kvs, { minDiskMb = 1024 } = {}) {
  const blockers = [];
  const warnings = [];
  if (kvs.SUDO === 'missing') blockers.push('The SSH user needs root or passwordless sudo (sudo -n)');
  if (kvs.APACHE === 'missing') blockers.push('Apache (apache2) is not installed');
  else if (kvs.APACHE === 'httpd' || kvs.LAYOUT === 'other') blockers.push('Only the Debian/Ubuntu apache2 layout (sites-available, a2ensite) is supported');
  if (kvs.MODS_MISSING) blockers.push(`Apache modules missing: ${kvs.MODS_MISSING} (enable with a2enmod)`);
  if (kvs.CERTBOT === 'missing') blockers.push('certbot is not installed');
  else if (kvs.CERTBOT_APACHE === 'no') warnings.push('certbot Apache plugin not detected (python3-certbot-apache)');
  if (kvs.NODE === 'missing') blockers.push('node is not installed');
  if (!kvs.PM2) blockers.push('pm2 is not installed');
  if (kvs.GIT === 'missing') blockers.push('git is not installed');
  if (kvs.PORT_BUSY) blockers.push(`Requested port ${kvs.PORT_BUSY} is already in use`);
  else if (!kvs.PORT || kvs.PORT === '0') blockers.push('No free port in the configured range');
  if (kvs.DISK_MB && Number(kvs.DISK_MB) < minDiskMb) blockers.push(`Free disk space is low (${kvs.DISK_MB} MB)`);
  return { ok: blockers.length === 0, blockers, warnings };
}
