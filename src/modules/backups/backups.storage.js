import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AppError } from '../../common/errors/app-error.js';
import { assertSafeUrl } from '../alert-channels/alert-channels.ssrf.js';
import { decrypt, encrypt } from '../platform/platform.crypto.js';
import { signRequest } from './backups.sigv4.js';

/**
 * Storage targets for encrypted backup artifacts (TASK-049). Every target implements
 *   upload({name, bytes}) -> {locationRef}; download({locationRef}) -> Buffer|null; remove({locationRef}); health().
 * Objects are already AES-256-GCM ciphertext when they reach a target; targets never see plaintext.
 */
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
export const DEFAULT_LOCAL_DIR = path.join(ROOT, '.data', 'backup-store');
export const DEFAULT_OFFSITE_CONFIG = path.join(ROOT, '.data', 'backup-offsite.enc');
const fileName = (name) => createHash('sha256').update(String(name)).digest('hex');

/** Local artifact store: file names are sha256(name), so a name can never traverse out of the directory. */
export function createLocalStore({ dir = DEFAULT_LOCAL_DIR } = {}) {
  const root = path.resolve(dir);
  const file = (ref) => path.join(root, `${fileName(String(ref).replace(/^local:\/\//, ''))}.bin`);
  return {
    kind: 'local',
    async upload({ name, bytes }) {
      mkdirSync(root, { recursive: true });
      writeFileSync(file(name), bytes);
      try {
        chmodSync(file(name), 0o600);
      } catch {
        /* windows */
      }
      return { locationRef: `local://${name}` };
    },
    async download({ locationRef }) {
      const p = file(locationRef);
      return existsSync(p) ? readFileSync(p) : null;
    },
    async remove({ locationRef }) {
      rmSync(file(locationRef), { force: true });
      return { removed: true };
    },
    async health() {
      return { healthy: true, kind: 'local' };
    },
  };
}

const bad = (code, msg, status = 422) => new AppError(status, code, msg);

/** Validates an offsite configuration. https only; the endpoint host is checked again (DNS) on every request. */
export function normalizeOffsiteConfig(input) {
  const endpoint = String(input?.endpoint ?? '').trim().replace(/\/+$/, '');
  let url;
  try {
    url = new URL(endpoint);
  } catch {
    throw bad('OFFSITE_ENDPOINT_INVALID', 'Endpoint must be a valid https URL');
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw bad('OFFSITE_ENDPOINT_INVALID', 'Endpoint must be an https URL without credentials, query or fragment');
  const bucket = String(input?.bucket ?? '');
  if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucket)) throw bad('OFFSITE_BUCKET_INVALID', 'Bucket name is not valid');
  const region = String(input?.region ?? 'us-east-1');
  if (!/^[a-z0-9-]{2,32}$/.test(region)) throw bad('OFFSITE_REGION_INVALID', 'Region is not valid');
  const prefix = String(input?.prefix ?? 'nodeteam').replace(/^\/+|\/+$/g, '');
  if (!/^[A-Za-z0-9_./-]{0,120}$/.test(prefix) || prefix.split('/').includes('..')) throw bad('OFFSITE_PREFIX_INVALID', 'Prefix is not valid');
  const accessKeyId = String(input?.accessKeyId ?? '');
  const secretAccessKey = String(input?.secretAccessKey ?? '');
  if (!/^[A-Za-z0-9_+=./-]{8,128}$/.test(accessKeyId)) throw bad('OFFSITE_KEY_INVALID', 'Access key id is not valid');
  if (secretAccessKey.length < 8 || secretAccessKey.length > 256 || /[\r\n]/.test(secretAccessKey)) throw bad('OFFSITE_KEY_INVALID', 'Secret access key is not valid');
  return { endpoint, bucket, region, prefix, accessKeyId, secretAccessKey, enabled: input?.enabled === true };
}

/** Public, secret-free view. */
export function publicOffsiteView(cfg) {
  if (!cfg) return { configured: false, enabled: false };
  return { configured: true, enabled: Boolean(cfg.enabled), endpoint: cfg.endpoint, bucket: cfg.bucket, region: cfg.region, prefix: cfg.prefix, accessKeyId: `${cfg.accessKeyId.slice(0, 4)}…`, secretConfigured: true };
}

/** Encrypted-at-rest offsite config (AES-256-GCM under CREDENTIAL_ENCRYPTION_KEY). Absent unless an Owner set it. */
export function createOffsiteConfigStore({ file = process.env.BACKUP_OFFSITE_CONFIG_FILE || DEFAULT_OFFSITE_CONFIG, key = () => process.env.CREDENTIAL_ENCRYPTION_KEY } = {}) {
  return {
    load() {
      if (!existsSync(file)) return null;
      try {
        return JSON.parse(decrypt(readFileSync(file), key()).toString('utf8'));
      } catch {
        return null; // unreadable or key changed: treated as not configured (fail closed)
      }
    },
    save(cfg) {
      mkdirSync(path.dirname(file), { recursive: true });
      writeFileSync(file, encrypt(JSON.stringify(cfg), key()));
      try {
        chmodSync(file, 0o600);
      } catch {
        /* windows */
      }
    },
    clear() {
      rmSync(file, { force: true });
    },
  };
}

/**
 * S3-compatible offsite target. Requests are signed with in-house SigV4, https only, redirects refused, every
 * request re-validates the endpoint (private/loopback/link-local addresses are blocked). Path-style addressing.
 */
export function createS3Store({ config, fetchImpl = (...a) => fetch(...a), now = () => new Date(), assertUrl = assertSafeUrl, timeoutMs = 60_000 }) {
  const cfg = normalizeOffsiteConfig({ ...config, enabled: true });
  const base = new URL(cfg.endpoint);
  const keyFor = (name) => `${cfg.prefix ? `${cfg.prefix}/` : ''}${String(name).replace(/^\/+/, '')}`;
  const refFor = (key) => `s3://${cfg.bucket}/${key}`;
  const parseRef = (ref) => {
    const m = /^s3:\/\/([^/]+)\/(.+)$/.exec(String(ref));
    if (!m || m[1] !== cfg.bucket || m[2].split('/').includes('..')) throw bad('OFFSITE_REF_INVALID', 'Location does not belong to the configured bucket');
    return m[2];
  };
  async function send(method, key, { body = Buffer.alloc(0), query = {} } = {}) {
    await assertUrl(cfg.endpoint);
    const p = `${base.pathname.replace(/\/+$/, '')}/${cfg.bucket}/${key}`;
    const signed = signRequest({ method, host: base.host, path: p, query, body, region: cfg.region, accessKeyId: cfg.accessKeyId, secretAccessKey: cfg.secretAccessKey, date: now() });
    const qs = Object.keys(query).length ? `?${new URLSearchParams(query).toString()}` : '';
    const { host, ...headers } = signed.headers;
    void host;
    const res = await fetchImpl(`${base.origin}${p.split('/').map(encodeURIComponent).join('/')}${qs}`, {
      method,
      headers,
      body: method === 'PUT' ? body : undefined,
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs),
    });
    return res;
  }
  return {
    kind: 's3',
    cfg: publicOffsiteView({ ...cfg, enabled: true }),
    async upload({ name, bytes }) {
      const key = keyFor(name);
      const res = await send('PUT', key, { body: Buffer.from(bytes) }).catch((e) => {
        if (e instanceof AppError) throw e;
        throw bad('OFFSITE_UNREACHABLE', 'Offsite storage could not be reached', 502);
      });
      if (!res.ok) throw bad('OFFSITE_UPLOAD_FAILED', `Offsite upload was rejected (HTTP ${res.status})`, 502);
      return { locationRef: refFor(key) };
    },
    async download({ locationRef }) {
      const res = await send('GET', parseRef(locationRef)).catch((e) => {
        if (e instanceof AppError) throw e;
        throw bad('OFFSITE_UNREACHABLE', 'Offsite storage could not be reached', 502);
      });
      if (res.status === 404) return null;
      if (!res.ok) throw bad('OFFSITE_DOWNLOAD_FAILED', `Offsite download failed (HTTP ${res.status})`, 502);
      return Buffer.from(await res.arrayBuffer());
    },
    async remove({ locationRef }) {
      const res = await send('DELETE', parseRef(locationRef));
      if (!res.ok && res.status !== 404) throw bad('OFFSITE_DELETE_FAILED', `Offsite delete failed (HTTP ${res.status})`, 502);
      return { removed: true };
    },
    async health() {
      try {
        const res = await send('HEAD', '', {});
        return { healthy: res.status < 500 && res.status !== 403 && res.status !== 401, status: res.status, kind: 's3' };
      } catch {
        return { healthy: false, kind: 's3' };
      }
    },
  };
}

/**
 * Routes by locationRef scheme. Uploads go to offsite only when it is configured AND enabled (resolved on every call
 * so an Owner change applies immediately), otherwise to the local artifact store.
 */
export function createStorageRouter({ local, resolveOffsite = () => null, legacy = null }) {
  const byRef = (ref) => {
    const r = String(ref);
    if (r.startsWith('local://')) return local;
    if (r.startsWith('s3://')) {
      const off = resolveOffsite();
      if (!off) throw bad('OFFSITE_NOT_CONFIGURED', 'Offsite storage is not configured or is disabled', 409);
      return off;
    }
    if (legacy) return legacy;
    throw bad('LOCATION_UNKNOWN', 'Unknown storage location');
  };
  const active = () => resolveOffsite() ?? local;
  return {
    get offsiteActive() {
      return Boolean(resolveOffsite());
    },
    target: active,
    upload: (a) => active().upload(a),
    download: (a) => byRef(a.locationRef).download(a),
    remove: (a) => byRef(a.locationRef).remove(a),
    health: () => active().health(),
  };
}

/** Builds the resolver used by the router: an enabled, decryptable config yields an S3 target, otherwise null. */
export function offsiteResolver(configStore, opts = {}) {
  return () => {
    const cfg = configStore?.load?.();
    if (!cfg?.enabled) return null;
    try {
      return createS3Store({ config: cfg, ...opts });
    } catch {
      return null;
    }
  };
}
