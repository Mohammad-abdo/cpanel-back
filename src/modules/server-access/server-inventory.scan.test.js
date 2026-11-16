import { describe, expect, it } from 'vitest';
import { isJunkProjectPath, parseInventory } from './server-inventory.scan.js';

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
`);
    expect(out.projects.map((p) => p.path).sort()).toEqual([
      '/var/www/api.example.com',
      '/var/www/shop.example.com',
    ]);
    expect(out.projects.find((p) => p.path.includes('shop')).type).toBe('laravel');
    expect(out.domains.map((d) => d.name)).toContain('shop.example.com');
    expect(out.databases[0].schemas).toEqual(['shop_db']);
  });

  it('flags dependency paths as junk', () => {
    expect(isJunkProjectPath('/var/www/app/node_modules/foo')).toBe(true);
    expect(isJunkProjectPath('/var/www/shop.example.com')).toBe(false);
  });
});
