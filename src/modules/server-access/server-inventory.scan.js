/**
 * Read-only SSH inventory: fixed script (no user input) + parsers for projects, vhosts, databases.
 * Never modifies the remote host.
 */

/**
 * Kept deliberately simple for /bin/sh compatibility (no bash-only arrays).
 * Each find is wrapped in timeout so a deep tree cannot hang the whole scan.
 */
export const INVENTORY_SCRIPT = [
  "echo '##meta'",
  'whoami',
  'hostname',
  'uname -s',
  "echo '##roots'",
  'ls -1d /var/www /var/www/* /home/*/public_html /home/*/www /home/*/domains/*/public_html /opt/apps/* /srv/www/* 2>/dev/null | head -n 200',
  "echo '##projects'",
  'timeout 15 find /var/www /opt/apps /srv/www -maxdepth 4 \\( -name package.json -o -name artisan -o -name wp-config.php -o -name manage.py -o -name go.mod -o -name composer.json -o -name Gemfile -o -name pom.xml \\) -type f 2>/dev/null | head -n 200',
  'timeout 15 find /home -maxdepth 5 \\( -path "*/public_html/*" -o -path "*/www/*" -o -path "*/domains/*/public_html/*" \\) \\( -name package.json -o -name artisan -o -name wp-config.php -o -name composer.json \\) -type f 2>/dev/null | head -n 200',
  "echo '##pm2'",
  'command -v pm2 >/dev/null 2>&1 && pm2 jlist 2>/dev/null | head -c 80000 || true',
  "echo '##vhosts_nginx'",
  'for f in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do if [ -e "$f" ]; then echo "FILE:$f"; grep -E "server_name|root |proxy_pass" "$f" 2>/dev/null | head -n 40; fi; done',
  "echo '##vhosts_apache'",
  'for f in /etc/apache2/sites-enabled/* /etc/httpd/conf.d/*.conf /etc/apache2/conf.d/*.conf; do if [ -e "$f" ]; then echo "FILE:$f"; grep -Ei "ServerName|ServerAlias|DocumentRoot|ProxyPass" "$f" 2>/dev/null | head -n 60; fi; done',
  "echo '##vhosts_grep'",
  'timeout 10 grep -RhoE "ServerName[[:space:]]+[^[:space:]]+" /etc/apache2 /etc/httpd 2>/dev/null | head -n 200 || true',
  'timeout 10 grep -RhoE "server_name[[:space:]]+[^;]+" /etc/nginx 2>/dev/null | head -n 200 || true',
  "echo '##mysql'",
  "mysql --batch --skip-column-names -e 'SHOW DATABASES' 2>/dev/null | head -n 200 || mysql --defaults-file=/etc/mysql/debian.cnf --batch --skip-column-names -e 'SHOW DATABASES' 2>/dev/null | head -n 200 || true",
  "echo '##postgres'",
  'psql -U postgres -tAc "SELECT datname FROM pg_database WHERE datistemplate = false" 2>/dev/null | head -n 200 || true',
  "echo '##engines'",
  'command -v mysql >/dev/null 2>&1 && echo mysql || true',
  'command -v mariadb >/dev/null 2>&1 && echo mysql || true',
  'command -v psql >/dev/null 2>&1 && echo postgres || true',
  "ss -tlnH 2>/dev/null | awk '{print $4}' | grep -E ':(3306|5432)$' | head -n 20 || true",
].join('\n');

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

  for (const line of sec.roots ?? []) {
    const root = line.trim();
    if (!root.startsWith('/')) continue;
    if (!/public_html$|\/www$/.test(root)) continue;
    if (seenPaths.has(root)) continue;
    seenPaths.add(root);
    const name = projectNameFromPath(root);
    const slug = slugify(name);
    if (!slug) continue;
    projects.push({ name, slug, path: root, marker: null, type: 'php', runtime: 'php', processManager: 'apache' });
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
    const sa = /ServerAlias\s+(.+)/i.exec(t);
    if (sa) {
      for (const part of sa[1].trim().split(/\s+/)) pushDomain(part, apacheFile, 'apache');
    }
    const doc = /DocumentRoot\s+(\S+)/i.exec(t);
    if (doc && domains.length) {
      const last = domains[domains.length - 1];
      if (last.confPath === apacheFile) last.root = doc[1];
    }
  }

  for (const line of sec.vhosts_grep ?? []) {
    const t = line.trim();
    const nginx = /server_name\s+(.+)/i.exec(t);
    if (nginx) {
      for (const part of nginx[1].replace(/;$/, '').trim().split(/\s+/)) pushDomain(part, null, 'nginx');
      continue;
    }
    const apache = /ServerName\s+(\S+)/i.exec(t);
    if (apache) pushDomain(apache[1], null, 'apache');
  }

  const mysqlSchemas = (sec.mysql ?? []).map((l) => l.trim()).filter((n) => n && !SYSTEM_DBS.has(n));
  const postgresSchemas = (sec.postgres ?? []).map((l) => l.trim()).filter((n) => n && !SYSTEM_DBS.has(n));

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
    meta: {
      user: sec.meta?.[0]?.trim() || null,
      hostname: sec.meta?.[1]?.trim() || null,
      os: sec.meta?.[2]?.trim() || null,
      rootsSampled: (sec.roots ?? []).map((l) => l.trim()).filter(Boolean).slice(0, 50),
    },
    scannedAt: new Date().toISOString(),
  };
}
