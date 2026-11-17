import { createBackupExecutor, resolveExecutorMode } from './backups.executor.js';
import { createLocalStore, createOffsiteConfigStore, createStorageRouter, offsiteResolver } from './backups.storage.js';

let runtime;

/**
 * Process-wide backup runtime (TASK-049). BACKUP_EXECUTOR=simulated (default) keeps every existing adapter; `ssh`
 * enables the real executor. The offsite target is disabled unless an Owner configured and enabled it.
 */
export function getBackupRuntime({ serverAccessService, adapters }) {
  if (!runtime) {
    const offsiteConfig = createOffsiteConfigStore();
    const storage = createStorageRouter({ local: createLocalStore(), resolveOffsite: offsiteResolver(offsiteConfig), legacy: adapters?.backupEngine ?? null });
    const executor = createBackupExecutor({ mode: resolveExecutorMode(), remote: serverAccessService?.runRemote?.bind(serverAccessService), storage });
    runtime = { executor, offsiteConfig };
  }
  return runtime;
}
