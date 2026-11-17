import { describe, expect, it } from 'vitest';
import {
  isGithubRemote,
  isJunkProjectPath,
  normalizeGitRemote,
  parseInventory,
  projectImportIssues,
} from './server-inventory.scan.js';

describe('parseInventory', () => {
  it('keeps site roots and drops node_modules packages', () => {
    const out = parseInventory(`
##meta
root
host
Linux
##roots
/var/www/shop.example.com
/var/www/api.example.com
/var/www/backup
##projects
/var/www/shop.example.com/artisan
/var/www/shop.example.com/node_modules/abort-controller/package.json
/var/www/api.example.com/package.json
/var/www/api.example.com/node_modules/lodash/package.json
##pm2
[]
##vhosts_nginx
FILE:/etc/nginx/sites-enabled/shop
  server_name shop.example.com;
  root /var/www/shop.example.com/public;
##vhosts_apache
##vhosts_grep
##mysql
shop_db
mysql
##postgres
##engines
mysql
##git
DIR:/var/www/api.example.com
REMOTE:git@github.com:acme/api.git
BRANCH:main
DIR:/var/www/shop.example.com
REMOTE:
BRANCH:
`);
    expect(out.projects.map((p) => p.path).sort()).toEqual([
      '/var/www/api.example.com',
      '/var/www/shop.example.com',
    ]);
    const shop = out.projects.find((p) => p.path.includes('shop'));
    const api = out.projects.find((p) => p.path.includes('api'));
    expect(shop.type).toBe('laravel');
    expect(shop.issues).toEqual(expect.arrayContaining(['no-git']));
    expect(api.remoteUrl).toBe('https://github.com/acme/api');
    expect(api.issues).toEqual(expect.arrayContaining(['github']));
    expect(out.domains.map((d) => d.name)).toContain('shop.example.com');
    expect(out.databases[0].schemas).toEqual(['shop_db']);
  });

  it('flags dependency paths as junk', () => {
    expect(isJunkProjectPath('/var/www/app/node_modules/foo')).toBe(true);
    expect(isJunkProjectPath('/var/www/shop.example.com')).toBe(false);
  });

  it('normalizes git remotes and builds issue codes', () => {
    expect(normalizeGitRemote('git@github.com:org/repo.git')).toBe('https://github.com/org/repo');
    expect(isGithubRemote('https://github.com/org/repo')).toBe(true);
    expect(projectImportIssues({ path: '/a', remoteUrl: null, domainName: null })).toEqual(
      expect.arrayContaining(['no-git', 'no-domain']),
    );
    expect(
      projectImportIssues(
        { path: '/a', remoteUrl: 'https://github.com/org/repo', domainName: 'a.test' },
        { knownRemotes: new Set(['https://github.com/org/repo']), knownPaths: new Set(['/a']) },
      ),
    ).toEqual(expect.arrayContaining(['already-known', 'github', 'repo-taken']));
  });
});
