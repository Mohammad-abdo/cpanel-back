import { describe, expect, it } from 'vitest';
import { parseInventory } from './server-inventory.scan.js';

describe('parseInventory', () => {
  it('parses projects, nginx domains and mysql schemas', () => {
    const out = parseInventory(`
##projects
/var/www/shop/artisan
/var/www/api/package.json
##pm2
[]
##vhosts_nginx
FILE:/etc/nginx/sites-enabled/shop
  server_name shop.example.com www.shop.example.com;
  root /var/www/shop/public;
  proxy_pass http://127.0.0.1:3000;
##vhosts_apache
##mysql
information_schema
shop_db
mysql
##postgres
##engines
mysql
0.0.0.0:3306
`);
    expect(out.projects.map((p) => p.slug)).toEqual(expect.arrayContaining(['shop', 'api']));
    expect(out.projects.find((p) => p.slug === 'shop').type).toBe('laravel');
    expect(out.domains.map((d) => d.name)).toEqual(expect.arrayContaining(['shop.example.com', 'www.shop.example.com']));
    expect(out.domains[0].confPath).toBe('/etc/nginx/sites-enabled/shop');
    expect(out.databases).toEqual([{ engine: 'mysql', port: 3306, schemas: ['shop_db'] }]);
  });
});
