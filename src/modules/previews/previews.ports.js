/**
 * TASK-045: per-preview port allocation from a configured range, with collision checks.
 * Pure: the caller supplies every port that is already taken (other previews, discovered listeners on the server).
 */
import { AppError } from '../../common/errors/app-error.js';

export const MIN_PORT = 1024;
export const MAX_PORT = 65535;
export const MAX_RANGE = 5000;

export function validatePortRange(start, end) {
  const ok = Number.isInteger(start) && Number.isInteger(end) && start >= MIN_PORT && end <= MAX_PORT && start <= end && end - start + 1 <= MAX_RANGE;
  if (!ok) throw new AppError(422, 'PREVIEW_PORT_RANGE_INVALID', `Port range must be inside ${MIN_PORT}-${MAX_PORT}, ordered, and at most ${MAX_RANGE} ports`);
}

/**
 * Starts at a spread position derived from the PR number (so concurrent previews rarely contend) and walks the range once.
 * Throws PREVIEW_PORTS_EXHAUSTED when every port is taken.
 */
export function allocatePort({ start, end, taken = [], seed = 0 }) {
  validatePortRange(start, end);
  const used = new Set(taken.map(Number));
  const size = end - start + 1;
  const first = Math.abs(Number(seed) || 0) % size;
  for (let i = 0; i < size; i += 1) {
    const port = start + ((first + i) % size);
    if (!used.has(port)) return port;
  }
  throw new AppError(409, 'PREVIEW_PORTS_EXHAUSTED', 'No free port is left in the preview port range');
}

/** Hostname for a preview: pr-<n>.<project slug>.<root domain>. Each label and the total length are bounded. */
export function previewHostname({ prNumber, slug, rootName }) {
  const host = `pr-${prNumber}.${slug}.${rootName}`.toLowerCase();
  const labels = host.split('.');
  const ok = Number.isInteger(prNumber) && prNumber > 0 && host.length <= 253 && labels.every((l) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l));
  if (!ok) throw new AppError(422, 'PREVIEW_HOSTNAME_INVALID', 'Project slug or root domain cannot form a valid preview hostname');
  return host;
}
