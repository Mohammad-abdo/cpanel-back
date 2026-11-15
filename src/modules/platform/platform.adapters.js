import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import path from 'node:path';

/**
 * Simulated adapters. They never touch a real server, DNS provider, ACME CA, database, backup target,
 * firewall or Wazuh. Real adapters (certbot, mysqldump, restic, ufw, Wazuh API) are NOT_RUN and must be
 * supplied by the deployment; every service takes these interfaces by injection.
 */
/**
 * Simulated offsite storage. In memory by default (tests). With `dir`, objects persist on disk so a
 * dev API restart does not make every stored backup unreadable. File names are sha256(name): no traversal.
 */
export function createSimulatedObjectStore(dir = null) {
  if (!dir) return new Map();
  const root = path.resolve(dir);
  mkdirSync(root, { recursive: true });
  const file = (name) => path.join(root, `${createHash('sha256').update(String(name)).digest('hex')}.bin`);
  return {
    set(name, bytes) { writeFileSync(file(name), bytes); },
    get(name) { const p = file(name); return existsSync(p) ? readFileSync(p) : undefined; },
    delete(name) { rmSync(file(name), { force: true }); },
  };
}

export function createSimulatedAdapters({ now = () => new Date(), storeDir = null } = {}) {
  const calls = [];
  const rec = (name, arg) => {
    calls.push({ name, arg });
  };
  const store = createSimulatedObjectStore(storeDir);

  return {
    simulated: true,
    calls,
    dns: {
      async upsert(record) { rec('dns.upsert', record); return { providerRef: 'sim-dns', ...record }; },
      async remove(record) { rec('dns.remove', record); return { removed: true }; },
      async resolve(name) { rec('dns.resolve', name); return { name, resolves: true }; },
    },
    webserver: {
      async validate(config) { rec('web.validate', config); return { ok: /server_name\s+[^;]+;/.test(config), errors: [] }; },
      async apply(input) { rec('web.apply', input); return { applied: true, backupRef: 'sim-vhost-backup' }; },
      async rollback(input) { rec('web.rollback', input); return { rolledBack: true }; },
    },
    acme: {
      async issue(input) {
        rec('acme.issue', input);
        return { provider: 'simulated-acme', expiresAt: new Date(now().getTime() + 90 * 86400000) };
      },
    },
    dbAdmin: {
      async createDatabase(input) { rec('db.create', input); return { created: true }; },
      async createUser(input) { rec('db.user', { ...input, password: '[REDACTED]' }); return { created: true }; },
      async dropDatabase(input) { rec('db.drop', input); return { dropped: true }; },
    },
    backupEngine: {
      // Real implementation: mysqldump --single-transaction --routines --triggers (consistent InnoDB snapshot).
      async dump({ kind, ref }) { rec('backup.dump', { kind, ref }); return { bytes: Buffer.from(`simulated-${kind}-dump-of-${ref}`), consistent: true, method: kind === 'db' ? 'single-transaction' : 'file-snapshot' }; },
      async upload({ name, bytes }) { rec('backup.upload', { name }); store.set(name, Buffer.from(bytes)); return { locationRef: `sim://offsite/${name}` }; },
      async download({ locationRef }) { rec('backup.download', { locationRef }); return store.get(locationRef.replace('sim://offsite/', '')) ?? null; },
      async remove({ locationRef }) { rec('backup.remove', { locationRef }); store.delete(locationRef.replace('sim://offsite/', '')); return { removed: true }; },
      async restore(input) { rec('backup.restore', { mode: input.mode, kinds: (input.items ?? []).map((i) => i.kind) }); return { restored: true, checksums: Object.fromEntries((input.items ?? []).map((i) => [i.kind, createHash('sha256').update(i.bytes).digest('hex')])) }; },
      async health(input) { rec('backup.health', input); return { healthy: true }; },
      async impact(input) { rec('backup.impact', input); return { tables: 'UNKNOWN', estimatedDowntimeSeconds: 0, overwrites: input.mode === 'inplace' }; },
    },
    wazuh: {
      async health() { rec('wazuh.health'); return { connected: true, simulated: true }; },
      async fetchAlerts({ since }) { rec('wazuh.alerts', { since }); return []; },
    },
    firewall: {
      async list(serverId) { rec('fw.list', serverId); return [{ action: 'allow', port: 22, proto: 'tcp', source: 'any' }]; },
      async apply(input) { rec('fw.apply', input); return { rollbackToken: createHash('sha256').update(JSON.stringify(input)).digest('hex').slice(0, 16) }; },
      async rollback(input) { rec('fw.rollback', input); return { rolledBack: true }; },
    },
    fleet: {
      async probe(serverId) { rec('fleet.probe', serverId); return { reachable: true, latencyMs: 5 }; },
    },
  };
}
