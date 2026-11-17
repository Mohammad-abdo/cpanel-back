/**
 * Read-only SSH inventory: fixed script (no user input) + parsers for projects, vhosts, databases.
 * Never modifies the remote host.
 */

/**
 * Site-oriented scan: shallow finds under web roots, pruning dependency trees.
 * Kept /bin/sh-compatible; each find is time-boxed.
 */
export const INVENTORY_SCRIPT = [
  "echo '##meta'",
  'whoami',
  'hostname',
  'uname -s',
  "echo '##roots'",
  'ls -1d /var/www/* /home/*/public_html /home/*/www /home/*/domains/*/public_html /opt/apps/* /srv/www/* 2>/dev/null | head -n 400',
  "echo '##projects'",
  // Prune dependency/cache dirs so we do not import every npm package as a "project".
  'timeout 20 find /var/www /opt/apps /srv/www -mindepth 1 -maxdepth 3 \\( -name node_modules -o -name vendor -o -name .git -o -name bower_components -o -name __pycache__ -o -name .cache -o -name .npm -o -name dist -o -name build -o -name .next -o -name coverage \\) -prune -o -type f \\( -name package.json -o -name artisan -o -name wp-config.php -o -name manage.py -o -name go.mod -o -name composer.json -o -name Gemfile -o -name pom.xml \\) -print 2>/dev/null | head -n 400',
  'timeout 15 find /home -mindepth 2 -maxdepth 6 \\( -name node_modules -o -name vendor -o -name .git \\) -prune -o \\( -path "*/public_html/*" -o -path "*/www/*" -o -path "*/domains/*/public_html/*" \\) -type f \\( -name package.json -o -name artisan -o -name wp-config.php -o -name composer.json \\) -print 2>/dev/null | head -n 200',
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
  // Git remotes for import plan issue codes (no-git / not-github / github).
  "echo '##git'",
  'timeout 25 find /var/www /opt/apps /srv/www /home -mindepth 1 -maxdepth 6 -type d -name .git 2>/dev/null | head -n 80 | while read g; do',
  '  d=$(dirname "$g");',
  '  remote=$(git -C "$d" remote get-url origin 2>/dev/null || true);',
  '  branch=$(git -C "$d" rev-parse --abbrev-ref HEAD 2>/dev/null || true);',
  '  printf "DIR:%s\\nREMOTE:%s\\nBRANCH:%s\\n" "$d" "$remote" "$branch";',
  'done',
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

/** Paths that are libraries/services, not deployable sites. */
export const JUNK_PATH_RE =
  /\/(node_modules|vendor|\.git|bower_components|__pycache__|\.cache|\.npm|coverage|\.turbo|\.yarn)(\/|$)/i;

const SKIP_ROOT_NAMES = new Set([
  'backup',
  'backups',
  'html',
  'cgi-bin',
  'default',
  'lost+found',
  'tmp',
  'temp',
  'cache',
  'logs',
  'log',
  'node_modules',
  'vendor',
]);

export function isJunkProjectPath(p) {
  const path = String(p ?? '');
  if (!path.startsWith('/')) return true;
  if (JUNK_PATH_RE.test(path)) return true;
  // Too deep under /var/www (site / optional app subfolder only)
  const www = path.match(/^\/var\/www\/([^/]+)(?:\/([^/]+))?$/);
  if (path.startsWith('/var/www/')) {
    if (!www) return true;
    if (SKIP_ROOT_NAMES.has(www[1].toLowerCase())) return true;
  }
  return false;
}

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

/** Normalize a git remote to an https URL when possible; null when empty. */
export function normalizeGitRemote(raw) {
  const s = String(raw ?? '').trim();
  if (!s) return null;
  if (/^git@github\.com:/i.test(s)) return `https://github.com/${s.replace(/^git@github\.com:/i, '').replace(/\.git$/i, '')}`;
  if (/^ssh:\/\/git@github\.com\//i.test(s)) return `https://github.com/${s.replace(/^ssh:\/\/git@github\.com\//i, '').replace(/\.git$/i, '')}`;
  if (/^https?:\/\/github\.com\//i.test(s)) return s.replace(/\.git$/i, '').replace(/\/$/, '');
  return s.replace(/\.git$/i, '');
}

export function isGithubRemote(url) {
  return /^https?:\/\/github\.com\//i.test(String(url ?? ''));
}

/** vercel-clone-style issue codes for an import plan row (SSH inventory). */
export function projectImportIssues(project, { knownPaths = new Set(), knownRemotes = new Set() } = {}) {
  const issues = [];
  if (knownPaths.has(project.path)) issues.push('already-known');
  if (!project.remoteUrl) issues.push('no-git');
  else if (!isGithubRemote(project.remoteUrl)) issues.push('not-github');
  else {
    issues.push('github');
    if (knownRemotes.has(project.remoteUrl.toLowerCase())) issues.push('repo-taken');
  }
  if (!project.domainName) issues.push('no-domain');
  return issues;
}

function projectNameFromPath(appDir) {
  const parts = appDir.split('/').filter(Boolean);
  const last = parts[parts.length - 1] || 'app';
  if (['public_html', 'html', 'www', 'public', 'current', 'release'].includes(last) && parts.length >= 2) {
    return parts[parts.length - 2];
  }
  // Prefer the site folder under /var/www
  if (parts[0] === 'var' && parts[1] === 'www' && parts[2]) return parts[2];
  return last;
}

/** Prefer site root over nested app packages when both exist. */
function scoreProject(path, marker) {
  let score = 0;
  if (/^\/var\/www\/[^/]+$/.test(path)) score += 50;
  if (/^\/var\/www\/[^/]+\/(backend|frontend|api|app|server|web|client)?$/.test(path)) score += 30;
  if (marker?.endsWith('artisan') || marker?.endsWith('wp-config.php')) score += 20;
  if (marker?.endsWith('composer.json') || marker?.endsWith('package.json')) score += 10;
  if (JUNK_PATH_RE.test(path)) score -= 100;
  score -= Math.min(path.split('/').length, 12);
  return score;
}

/** Parse INVENTORY_SCRIPT stdout into structured candidates. */
export function parseInventory(text) {
  const sec = sections(text);
  const byPath = new Map();

  const addProject = (raw) => {
    if (!raw?.path || isJunkProjectPath(raw.path)) return;
    const name = raw.name || projectNameFromPath(raw.path);
    const slug = raw.slug || slugify(name);
    if (!slug || SKIP_ROOT_NAMES.has(slug)) return;
    const candidate = {
      name,
      slug,
      path: raw.path,
      marker: raw.marker ?? null,
      type: raw.type ?? 'custom',
      runtime: raw.runtime ?? null,
      processManager: raw.processManager ?? 'none',
      kind: 'site',
    };
    const prev = byPath.get(candidate.path);
    if (!prev || scoreProject(candidate.path, candidate.marker) > scoreProject(prev.path, prev.marker)) {
      byPath.set(candidate.path, candidate);
    }
  };

  for (const line of sec.projects ?? []) {
    const marker = line.trim();
    if (!marker.startsWith('/')) continue;
    if (isJunkProjectPath(marker)) continue;
    const appDir = marker.replace(/\/[^/]+$/, '');
    if (isJunkProjectPath(appDir)) continue;
    const name = projectNameFromPath(appDir);
    const detected = detectType(marker, name);
    addProject({ name, path: appDir, marker, ...detected });
  }

  // Site folders under web roots without a marker still count as sites (static/php).
  for (const line of sec.roots ?? []) {
    const root = line.trim();
    if (!root.startsWith('/') || root === '/var/www') continue;
    if (isJunkProjectPath(root)) continue;
    const base = root.split('/').pop();
    if (SKIP_ROOT_NAMES.has(String(base).toLowerCase())) continue;
    // Only add root as project if nothing better already covers this site
    const covered = [...byPath.keys()].some((p) => p === root || p.startsWith(`${root}/`));
    if (covered) continue;
    addProject({
      name: projectNameFromPath(root),
      path: root,
      marker: null,
      type: 'php',
      runtime: 'php',
      processManager: 'apache',
    });
  }

  // PM2 apps only when cwd is a real site path (not node_modules)
  try {
    const raw = (sec.pm2 ?? []).join('').trim();
    if (raw.startsWith('[')) {
      for (const proc of JSON.parse(raw)) {
        const cwd = proc?.pm2_env?.pm_cwd || proc?.pm2_env?.cwd;
        const name = proc?.name || proc?.pm2_env?.name;
        if (!cwd || !name || isJunkProjectPath(cwd)) continue;
        addProject({
          name,
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

  // Collapse nested packages into their site root when possible
  const projects = [...byPath.values()].sort((a, b) => a.name.localeCompare(b.name));
  const collapsed = [];
  for (const p of projects) {
    const parent = collapsed.find((c) => p.path !== c.path && p.path.startsWith(`${c.path}/`));
    if (parent) {
      // Keep nested only if it looks like a first-class app folder
      const rel = p.path.slice(parent.path.length + 1);
      if (!/^(backend|frontend|api|app|server|web|client|admin)$/i.test(rel)) continue;
    }
    collapsed.push(p);
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

  // Parse ##git blocks: DIR / REMOTE / BRANCH triples.
  const gitByDir = new Map();
  let gitDir = null;
  for (const line of sec.git ?? []) {
    const t = line.trim();
    if (t.startsWith('DIR:')) {
      gitDir = t.slice(4).trim();
      continue;
    }
    if (!gitDir) continue;
    if (t.startsWith('REMOTE:')) {
      const remoteUrl = normalizeGitRemote(t.slice(7));
      const prev = gitByDir.get(gitDir) ?? { remoteUrl: null, branch: null };
      prev.remoteUrl = remoteUrl;
      gitByDir.set(gitDir, prev);
    } else if (t.startsWith('BRANCH:')) {
      const prev = gitByDir.get(gitDir) ?? { remoteUrl: null, branch: null };
      prev.branch = t.slice(7).trim() || null;
      gitByDir.set(gitDir, prev);
    }
  }

  const attachGit = (p) => {
    const exact = gitByDir.get(p.path);
    if (exact) return exact;
    // Prefer longest matching git root under or equal to the project path.
    let best = null;
    let bestLen = -1;
    for (const [dir, info] of gitByDir) {
      if (p.path === dir || p.path.startsWith(`${dir}/`) || dir.startsWith(`${p.path}/`)) {
        if (dir.length > bestLen) {
          best = info;
          bestLen = dir.length;
        }
      }
    }
    return best;
  };

  // Attach matching domain names / ports / git to site projects for the import plan UI
  for (const p of collapsed) {
    const match = domains.find((d) => d.name === p.name || p.path.endsWith(`/${d.name}`) || p.path.includes(`/${d.name}/`) || d.root === p.path || (d.root && d.root.startsWith(`${p.path}/`)));
    if (match) {
      p.domainName = match.name;
      if (match.upstreamPort != null) p.upstreamPort = match.upstreamPort;
    }
    const git = attachGit(p);
    if (git) {
      p.remoteUrl = git.remoteUrl;
      p.branch = git.branch;
    } else {
      p.remoteUrl = null;
      p.branch = null;
    }
    p.issues = projectImportIssues(p);
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
    projects: collapsed,
    domains,
    databases,
    meta: {
      user: sec.meta?.[0]?.trim() || null,
      hostname: sec.meta?.[1]?.trim() || null,
      os: sec.meta?.[2]?.trim() || null,
      rootsSampled: (sec.roots ?? []).map((l) => l.trim()).filter(Boolean).slice(0, 80),
    },
    scannedAt: new Date().toISOString(),
  };
}
