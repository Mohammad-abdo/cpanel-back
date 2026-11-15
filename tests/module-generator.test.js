import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, mkdir, copyFile, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
const tempDirs = [];
afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map(path => rm(path, { recursive: true, force: true })));
});
async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'nodeteam-module-'));
  tempDirs.push(root);
  await mkdir(join(root, 'scripts'));
  await mkdir(join(root, 'apps/api/src/modules'), { recursive: true });
  const script = join(root, 'scripts/create-module.mjs');
  await copyFile(fileURLToPath(new URL('../../../scripts/create-module.mjs', import.meta.url)), script);
  return { root, run: name => spawnSync(process.execPath, [script, name], { encoding: 'utf8', cwd: tmpdir() }) };
}
describe('module scaffolding', () => {
  it('creates all four layers from any working directory and refuses overwrites', async () => {
    const { root, run } = await fixture();
    expect(run('projects').status).toBe(0);
    const target = join(root, 'apps/api/src/modules/projects');
    expect((await readdir(target)).sort()).toEqual(['projects.controller.js', 'projects.routes.js', 'projects.service.js', 'projects.validator.js']);
    const before = await readFile(join(target, 'projects.routes.js'), 'utf8');
    expect(run('projects').status).toBe(1);
    expect(await readFile(join(target, 'projects.routes.js'), 'utf8')).toBe(before);
    expect(before).toContain("import { Router } from 'express';");
    expect(before).not.toContain('\\n');
  });
  it('rejects traversal, mixed case and invalid names without writing modules', async () => {
    const { root, run } = await fixture();
    for (const name of ['../escape', 'Projects', 'a/b', '', 'a'.repeat(61)]) {
      expect(run(name).status).toBe(1);
    }
    expect(await readdir(join(root, 'apps/api/src/modules'))).toEqual([]);
  });
});
