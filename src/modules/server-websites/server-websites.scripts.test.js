import { describe, expect, it } from 'vitest';
import { parseCaddySites, parseWebsitesOutput } from './server-websites.scripts.js';

describe('server-websites scripts', () => {
  it('parses Caddyfile host blocks', () => {
    const sites = parseCaddySites(`
FILE:/etc/caddy/sites/api.example.com.caddy
api.example.com {
root * /var/www/api
reverse_proxy 127.0.0.1:5000
tls internal
`);
    expect(sites[0]).toEqual(
      expect.objectContaining({
        hostname: 'api.example.com',
        https: true,
        configFile: '/etc/caddy/sites/api.example.com.caddy',
      }),
    );
  });

  it('merges apache/nginx/caddy into the live list', () => {
    const out = parseWebsitesOutput(`
##apache
unavailable=apache
##nginx
unavailable=nginx
##caddy
FILE:/etc/caddy/Caddyfile
shop.example.com {
root * /var/www/shop
`);
    expect(out.caddy).toBe(true);
    expect(out.apache).toBe(false);
    expect(out.nginx).toBe(false);
    expect(out.sites).toEqual([
      expect.objectContaining({ server: 'caddy', hostname: 'shop.example.com', https: true }),
    ]);
  });
});
