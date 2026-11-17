/**
 * Static XSS corpus / sanitizer contract (no DOM / jsdom).
 * Full sanitizeMailHtml execution remains NOT_RUN until Owner allows a jsdom run.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { XSS_CORPUS, iframeCsp } from '../../../apps/webmail/src/xss-corpus.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const safeHtml = readFileSync(join(root, 'apps/webmail/src/safe-html.js'), 'utf8');

describe('webmail XSS corpus (static contract)', () => {
  it('exposes a non-empty corpus with assertions', () => {
    expect(XSS_CORPUS.length).toBeGreaterThanOrEqual(8);
    for (const c of XSS_CORPUS) {
      expect(c.id).toBeTruthy();
      expect(typeof c.html).toBe('string');
      expect(typeof c.allowRemote).toBe('boolean');
      expect(c.mustNotMatch?.length || c.mustMatch?.length).toBeGreaterThan(0);
    }
  });

  it('sanitizer forbids high-risk tags referenced by the corpus', () => {
    for (const tag of ['script', 'iframe', 'object', 'svg', 'math', 'style', 'form', 'base', 'meta', 'link']) {
      expect(safeHtml).toMatch(new RegExp(`['"]${tag}['"]`));
    }
    expect(safeHtml).toMatch(/ALLOW_DATA_ATTR:\s*false/);
    expect(safeHtml).toMatch(/FORBID_ATTR:[\s\S]*srcset/);
  });

  it('iframe CSP stays locked down', () => {
    expect(iframeCsp(false)).toContain("default-src 'none'");
    expect(iframeCsp(false)).not.toContain('img-src https:');
    expect(iframeCsp(true)).toContain('img-src https: data:');
  });
});
