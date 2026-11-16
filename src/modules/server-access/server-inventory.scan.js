/**
 * Read-only SSH inventory: fixed script (no user input) + parsers for projects, vhosts, databases.
 * Never modifies the remote host.
 */

/** Marker files that identify an application root (depth-limited find). */
export const INVENTORY_SCRIPT = [
  "echo '##projects'",
  [
    'for root in /var/www /var/www/html /home/*/public_html /home/*/www /home/*/domains/*/public_html /opt/apps /srv /srv/www; do',
    '  [ -d "$root" ] || continue',
    '  find "$root" -maxdepth 4 \\( -type f \\( -name package.json -o -name artisan -o -name wp-config.php -o -name manage.py -o -name go.mod -o -name composer.json -o -name Gemfile -o -name pom.xml \\) \\) 2>/dev/null',
    'done | head -n 300',
  ].join(' '),
  "echo '##pm2'",
  'command -v pm2 >/dev/null 2>&1 && pm2 jlist 2>/dev/null | head -c 80000 || true',
  "echo '##vhosts_nginx'",
  [
    'for f in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do',
    '  [ -f "$f" ] || [ -L "$f" ] || continue',
    '  echo "FILE:$f"',
    '  grep -E "server_name|root |proxy_pass|listen " "$f" 2>/dev/null | head -n 40',
    'done',
  ].join(' '),
  "echo '##vhosts_apache'",
  [
    'for f in /etc/apache2/sites-enabled/* /etc/httpd/conf.d/*.conf; do',
    '  [ -f "$f" ] || [ -L "$f" ] || continue',
    '  echo "FILE:$f"',
    '  grep -Ei "ServerName|DocumentRoot|ProxyPass |Listen " "$f" 2>/dev/null | head -n 40',
    'done',
  ].join(' '),
  "echo '##mysql'",
  "mysql --batch --skip-column-names -e 'SHOW DATABASES' 2>/dev/null | head -n 200 || mariadb --batch --skip-column-names -e 'SHOW DATABASES' 2>/dev/null | head -n 200 || true",
  "echo '##postgres'",
  "psql -U postgres -tAc \"SELECT datname FROM pg_database WHERE datistemplate = false\" 2>/dev/null | head -n 200 || sudo -n -u postgres psql -tAc \"SELECT datname FROM pg_database WHERE datistemplate = false\" 2>/dev/null | head -n 200 || true",
  "echo '##engines'",
  'command -v mysql >/dev/null 2>&1 && echo mysql || command -v mariadb >/dev/null 2>&1 && echo mysql || true',
  'command -v psql >/dev/null 2>&1 && echo postgres || true',
  "ss -tlnH 2>/dev/null | awk '{print $4}' | grep -E ':(3306|5432)$' | head -n 20 || true",
].join('; ');

const SYSTEM_DBS = new Set([
  'mysql',
  'sys',
  'information_schema',
  'performance_schema',
  'postgres',
  'template0',
  'template1',
]);

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

function detectType(markerFile, dirName) {
  const base = markerFile.split('/').pop();
  if (base === 'artisan') return { type: 'laravel', runtime: 'php', processManager: 'php-fpm' };
  if (base === 'wp-config.php') return { type: 'wordpress', runtime: 'php', processManager: 'php-fpm' };
  if (base === 'manage.py') return { type: 'django', runtime: 'python', processManager: 'gunicorn' };
  if (base === 'go.mod') return { type: 'go', runtime: 'go', processManager: 'systemd' };
  if (base === 'Gemfile') return { type: 'rails', runtime: 'ruby', processManager: 'systemd' };
  if (base === 'pom.xml') return { type: 'java', runtime: 'java', processManager: 'systemd' };
  if (base === 'composer.json') return { type: 'php', runtime: 'php', processManager: 'php-fpm' };
  if (base === 'package.json') {
    const n = dirName.toLowerCase();
    if (n.includes('next')) return { type: 'nextjs', runtime: 'node', processManager: 'pm2' };
    if (n.includes('nuxt')) return { type: 'nuxt', runtime: 'node', processManager: 'pm2' };
    return { type: 'node', runtime: 'node', processManager: 'pm2' };
  }
  return { type: 'custom', runtime: null, processManager: 'none' };
}

function slugify(name) {
  return String(name)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 63);
}

function projectNameFromPath(appDir) {
  const parts = appDir.split('/').filter(Boolean);
  const last = parts[parts.length - 1] || 'app';
  if (['public_html', 'html', 'www', 'public', 'current', 'release'].includes(last) && parts.length >= 2) {
    return parts[parts.length - 2];
  }
  return last;
}

/** Parse INVENTORY_SCRIPT stdout into structured candidates. */
export function parseInventory(text) {
  const sec = sections(text);
  const projects = [];
  const seenPaths = new Set();

  for (const line of sec.projects ?? []) {
    const marker = line.trim();
    if (!marker.startsWith('/')) continue;
    const appDir = marker.replace(/\/[^/]+$/, '');
    if (seenPaths.has(appDir)) continue;
    seenPaths.add(appDir);
    const name = projectNameFromPath(appDir);
    const slug = slugify(name);
    if (!slug) continue;
    const detected = detectType(marker, name);
    projects.push({
      name,
      slug,
      path: appDir,
      marker,
      ...detected,
    });
  }

  // PM2 apps that are not under the scanned trees
  try {
    const raw = (sec.pm2 ?? []).join('').trim();
    if (raw.startsWith('[')) {
      const list = JSON.parse(raw);
      for (const proc of list) {
        const cwd = proc?.pm2_env?.pm_cwd || proc?.pm2_env?.cwd;
        const name = proc?.name || proc?.pm2_env?.name;
        if (!cwd || !name) continue;
        if (seenPaths.has(cwd)) continue;
        seenPaths.add(cwd);
        const slug = slugify(name);
        if (!slug) continue;
        projects.push({
          name,
          slug,
          path: cwd,
          type: 'node',
          runtime: 'node',
          processManager: 'pm2',
          marker: null,
        });
      }
    }
  } catch {
    /* ignore malformed pm2 json */
  }

  const domains = [];
  const pushDomain = (name, confPath, webserver, extra = {}) => {
    const n = String(name).toLowerCase().replace(/\.$/, '');
    if (!n || n === '_' || n === 'default' || n.includes('*') || n.includes(' ')) return;
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(n)) return;
    if (domains.some((d) => d.name === n)) return;
    domains.push({ name: n, confPath, webserver, ...extra });
  };

  let nginxFile = null;
  for (const line of sec.vhosts_nginx ?? []) {
    const t = line.trim();
    if (t.startsWith('FILE:')) {
      nginxFile = t.slice(5).trim();
      continue;
    }
    const sn = /server_name\s+([^;]+);?/.exec(t);
    if (sn) {
      for (const part of sn[1].trim().split(/\s+/)) pushDomain(part, nginxFile, 'nginx');
    }
    const root = /^\s*root\s+([^;]+);?/.exec(t);
    if (root && domains.length) {
      const last = domains[domains.length - 1];
      if (last.confPath === nginxFile) last.root = root[1].trim();
    }
    const proxy = /proxy_pass\s+http:\/\/127\.0\.0\.1:(\d+)/.exec(t);
    if (proxy && domains.length) {
      const last = domains[domains.length - 1];
      if (last.confPath === nginxFile) last.upstreamPort = Number(proxy[1]);
    }
  }

  let apacheFile = null;
  for (const line of sec.vhosts_apache ?? []) {
    const t = line.trim();
    if (t.startsWith('FILE:')) {
      apacheFile = t.slice(5).trim();
      continue;
    }
    const sn = /ServerName\s+(\S+)/i.exec(t);
    if (sn) pushDomain(sn[1], apacheFile, 'apache');
    const doc = /DocumentRoot\s+(\S+)/i.exec(t);
    if (doc && domains.length) {
      const last = domains[domains.length - 1];
      if (last.confPath === apacheFile) last.root = doc[1];
    }
  }

  const mysqlSchemas = (sec.mysql ?? [])
    .map((l) => l.trim())
    .filter((n) => n && !SYSTEM_DBS.has(n));
  const postgresSchemas = (sec.postgres ?? [])
    .map((l) => l.trim())
    .filter((n) => n && !SYSTEM_DBS.has(n));

  const engines = new Set();
  for (const line of sec.engines ?? []) {
    const t = line.trim();
    if (t === 'mysql' || t === 'postgres') engines.add(t);
    if (/:3306$/.test(t)) engines.add('mysql');
    if (/:5432$/.test(t)) engines.add('postgres');
  }
  if (mysqlSchemas.length) engines.add('mysql');
  if (postgresSchemas.length) engines.add('postgres');

  const databases = [];
  if (engines.has('mysql') || mysqlSchemas.length) {
    databases.push({ engine: 'mysql', port: 3306, schemas: mysqlSchemas });
  }
  if (engines.has('postgres') || postgresSchemas.length) {
    databases.push({ engine: 'postgres', port: 5432, schemas: postgresSchemas });
  }

  return {
    projects,
    domains,
    databases,
    scannedAt: new Date().toISOString(),
  };
}
