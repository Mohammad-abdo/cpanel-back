/**
 * Read-only live web-site discovery over SSH (vercel-clone websites:list parity).
 * Fixed scripts only — no user input reaches the shell.
 */

export const WEBSITES_SCRIPT = [
  "echo '##apache'",
  'if command -v apache2ctl >/dev/null 2>&1; then apache2ctl -S 2>&1 | head -n 400; elif command -v apachectl >/dev/null 2>&1; then apachectl -S 2>&1 | head -n 400; else echo unavailable=apache; fi',
  "echo '##nginx'",
  'if command -v nginx >/dev/null 2>&1; then nginx -T 2>&1 | head -n 800; else echo unavailable=nginx; fi',
  "echo '##caddy'",
  'if command -v caddy >/dev/null 2>&1; then for f in /etc/caddy/Caddyfile /etc/caddy/sites/*.caddy /etc/caddy/*.caddy; do if [ -e "$f" ]; then echo "FILE:$f"; grep -E "^[^#[:space:]].*\\{|root |reverse_proxy |redir |tls " "$f" 2>/dev/null | head -n 80; fi; done; else echo unavailable=caddy; fi',
].join('\n');

/** Pure: vhosts from `apachectl -S` / `apache2ctl -S`. */
export function parseApacheVhosts(output) {
  const vhosts = [];
  let current = null;
  for (const line of String(output ?? '').split('\n')) {
    const named = line.match(/^\s+port (\d+) namevhost (\S+) \((.+):\d+\)/);
    const single = line.match(/^\S+:(\d+)\s+(\S+)\s+\((.+):\d+\)/);
    const alias = line.match(/^\s+alias (\S+)/);
    const m = named ?? single;
    if (m) {
      current = { port: Number(m[1]), hostname: m[2].toLowerCase(), configFile: m[3], aliases: [] };
      vhosts.push(current);
    } else if (alias && current) {
      current.aliases.push(alias[1].toLowerCase());
    }
  }
  return vhosts;
}

/** Pure: simplified nginx server_name + listen extraction from `nginx -T` (capped). */
export function parseNginxServers(dump) {
  const servers = [];
  let file = null;
  let depth = 0;
  let serverDepth = -1;
  let current = null;
  for (const raw of String(dump ?? '').split('\n')) {
    const header = raw.match(/^# configuration file (.+):\s*$/);
    if (header) {
      file = header[1];
      depth = 0;
      serverDepth = -1;
      current = null;
      continue;
    }
    const line = raw.replace(/#.*$/, '');
    if (/^\s*server\s*\{/.test(line) && serverDepth < 0) {
      current = { names: [], ports: [], https: false, configFile: file };
      servers.push(current);
      serverDepth = depth;
    }
    if (current) {
      const names = line.match(/(?:^|[{;])\s*server_name\s+([^;]+);/);
      if (names) current.names.push(...names[1].trim().split(/\s+/).map((n) => n.toLowerCase()));
      const listen = line.match(/(?:^|[{;])\s*listen\s+([^;]+);/);
      if (listen) {
        const port = listen[1].match(/(?:^|:|\s)(\d{2,5})(?:\s|$)/);
        if (port) current.ports.push(Number(port[1]));
        if (/\bssl\b|\bquic\b/.test(listen[1])) current.https = true;
      }
    }
    depth += (line.match(/\{/g) ?? []).length - (line.match(/\}/g) ?? []).length;
    if (current && serverDepth >= 0 && depth <= serverDepth) {
      current = null;
      serverDepth = -1;
    }
  }
  return servers;
}

const IGNORED = new Set(['_', 'localhost', 'default', 'default_server', '""']);
function isRealHostname(name) {
  return !IGNORED.has(name) && /^[a-z0-9*][a-z0-9.*-]*\.[a-z0-9-]+$/i.test(name) && !/^\d+(\.\d+){3}$/.test(name);
}

/** Pure: Caddyfile site blocks (`host {` + optional tls / reverse_proxy). */
export function parseCaddySites(dump) {
  const sites = [];
  let file = null;
  let current = null;
  for (const raw of String(dump ?? '').split('\n')) {
    const t = raw.trim();
    if (t.startsWith('FILE:')) {
      file = t.slice(5).trim();
      current = null;
      continue;
    }
    const site = /^([a-z0-9.*-]+)\s*\{/i.exec(t);
    if (site) {
      const hostname = site[1].replace(/^\*\./, '').toLowerCase();
      current = {
        hostname,
        aliases: [],
        ports: [80, 443],
        https: true,
        configFile: file,
      };
      sites.push(current);
      continue;
    }
    if (!current) continue;
    if (/^tls\s+off\b/i.test(t)) {
      current.https = false;
      current.ports = [80];
    } else if (/^tls\b/i.test(t)) {
      current.https = true;
      if (!current.ports.includes(443)) current.ports.push(443);
    }
  }
  return sites;
}

/** Combine apache + nginx + caddy sections into a flat site list. */
export function parseWebsitesOutput(stdout) {
  const sec = {};
  let cur = null;
  for (const line of String(stdout ?? '').replace(/\r/g, '').split('\n')) {
    const h = /^##(\w+)$/.exec(line.trim());
    if (h) {
      cur = h[1];
      sec[cur] = [];
    } else if (cur) sec[cur].push(line);
  }
  const sites = [];
  const apacheText = (sec.apache ?? []).join('\n');
  const nginxText = (sec.nginx ?? []).join('\n');
  const caddyText = (sec.caddy ?? []).join('\n');
  const apacheUp = /unavailable=apache/.test(apacheText);
  const nginxUp = /unavailable=nginx/.test(nginxText);
  const caddyUp = /unavailable=caddy/.test(caddyText);

  if (!apacheUp) {
    for (const v of parseApacheVhosts(apacheText)) {
      if (!isRealHostname(v.hostname)) continue;
      sites.push({
        server: 'apache',
        hostname: v.hostname,
        aliases: v.aliases.filter(isRealHostname),
        ports: [v.port],
        https: v.port === 443,
        configFile: v.configFile,
      });
    }
  }
  if (!nginxUp) {
    for (const s of parseNginxServers(nginxText)) {
      const host = s.names.find(isRealHostname);
      if (!host) continue;
      sites.push({
        server: 'nginx',
        hostname: host,
        aliases: s.names.filter((n) => n !== host && isRealHostname(n)),
        ports: [...new Set(s.ports)].sort((a, b) => a - b),
        https: s.https || s.ports.includes(443),
        configFile: s.configFile,
      });
    }
  }
  if (!caddyUp) {
    for (const s of parseCaddySites(caddyText)) {
      if (!isRealHostname(s.hostname)) continue;
      sites.push({
        server: 'caddy',
        hostname: s.hostname,
        aliases: s.aliases.filter(isRealHostname),
        ports: [...new Set(s.ports)].sort((a, b) => a - b),
        https: s.https,
        configFile: s.configFile,
      });
    }
  }

  // Dedupe hostname+server
  const seen = new Set();
  const out = [];
  for (const s of sites) {
    const key = `${s.server}:${s.hostname}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(s);
    if (out.length >= 200) break;
  }
  return {
    apache: !apacheUp,
    nginx: !nginxUp,
    caddy: !caddyUp,
    sites: out,
  };
}
