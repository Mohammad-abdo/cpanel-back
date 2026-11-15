import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile, rm, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AppError } from '../../common/errors/app-error.js';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
export const DEFAULT_ARTIFACT_DIR = path.join(REPO_ROOT, '.data', 'artifacts');
export const MAX_ARTIFACT_BYTES = 25 * 1024 * 1024;

/**
 * Filesystem artifact store (same put/get/remove port). The caller-supplied ref is never used as a path:
 * files are named by sha256(ref), so traversal is impossible. Each artifact is a `<id>.bin` body plus a
 * `<id>.json` sidecar holding metadata, a content checksum and expiresAt. get() returns expiresAt so the
 * service can answer 410; pruneExpired() deletes expired files (worker hook).
 */
export function createFileArtifactStore({
  dir = process.env.NT_ARTIFACT_DIR || DEFAULT_ARTIFACT_DIR,
  maxBytes = MAX_ARTIFACT_BYTES,
  now = () => new Date(),
} = {}) {
  const root = path.resolve(dir);
  const idOf = (ref) => createHash('sha256').update(String(ref)).digest('hex');
  const bodyPath = (id) => path.join(root, `${id}.bin`);
  const metaPath = (id) => path.join(root, `${id}.json`);
  const sum = (bytes) => createHash('sha256').update(bytes).digest('hex');

  return {
    async put(ref, body, meta = {}) {
      const bytes = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
      if (bytes.length > maxBytes) throw new AppError(413, 'ARTIFACT_TOO_LARGE', 'Artifact exceeds the size limit');
      const id = idOf(ref);
      await mkdir(root, { recursive: true });
      await writeFile(bodyPath(id), bytes);
      await writeFile(
        metaPath(id),
        JSON.stringify({
          ...meta,
          expiresAt: meta.expiresAt ? new Date(meta.expiresAt).toISOString() : null,
          checksum: sum(bytes),
          sizeBytes: bytes.length,
          isText: !Buffer.isBuffer(body),
        }),
      );
      return ref;
    },
    async get(ref) {
      const id = idOf(ref);
      try {
        const meta = JSON.parse(await readFile(metaPath(id), 'utf8'));
        const bytes = await readFile(bodyPath(id));
        if (sum(bytes) !== meta.checksum) throw new AppError(500, 'ARTIFACT_CORRUPT', 'Artifact checksum mismatch');
        return {
          ...meta,
          expiresAt: meta.expiresAt ? new Date(meta.expiresAt) : null,
          body: meta.isText ? bytes.toString('utf8') : bytes,
        };
      } catch (err) {
        if (err.code === 'ENOENT') return null;
        throw err;
      }
    },
    async remove(ref) {
      const id = idOf(ref);
      await rm(bodyPath(id), { force: true });
      await rm(metaPath(id), { force: true });
    },
    async pruneExpired() {
      let removed = 0;
      let names = [];
      try {
        names = await readdir(root);
      } catch {
        return { removed };
      }
      for (const n of names.filter((x) => x.endsWith('.json'))) {
        const id = n.slice(0, -5);
        try {
          const meta = JSON.parse(await readFile(path.join(root, n), 'utf8'));
          if (meta.expiresAt && new Date(meta.expiresAt) <= now()) {
            await rm(bodyPath(id), { force: true });
            await rm(path.join(root, n), { force: true });
            removed += 1;
          }
        } catch {
          /* skip unreadable sidecar */
        }
      }
      return { removed };
    },
  };
}

/**
 * Memory artifact store (tests only). Rendered bytes do not survive an API restart.
 */
export function createMemoryArtifactStore() {
  const files = new Map();
  return {
    async put(ref, body, meta) {
      files.set(ref, { body, ...meta });
      return ref;
    },
    async get(ref) {
      return files.get(ref) ?? null;
    },
    async remove(ref) {
      files.delete(ref);
    },
    get size() {
      return files.size;
    },
  };
}
