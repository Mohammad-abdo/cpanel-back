/**
 * Executes sanitizeMailHtml against the webmail XSS corpus under jsdom.
 * Complements the static contract in webmail-xss-corpus-static.test.js.
 */
import { JSDOM } from 'jsdom';
import { describe, expect, it } from 'vitest';
import { sanitizeMailHtml } from '../../webmail/src/safe-html.js';
import { XSS_CORPUS, iframeCsp } from '../../webmail/src/xss-corpus.js';

function runCase(c) {
  const { window } = new JSDOM('<!doctype html><html><body></body></html>');
  return sanitizeMailHtml(c.html, c.allowRemote, window);
}

describe('webmail XSS corpus (jsdom execution)', () => {
  it.each(XSS_CORPUS.map((c) => [c.id, c]))('%s', (_id, c) => {
    const out = runCase(c);
    for (const re of c.mustNotMatch ?? []) expect(out).not.toMatch(re);
    for (const re of c.mustMatch ?? []) expect(out).toMatch(re);
  });

  it('keeps iframe CSP helpers aligned with allowRemote', () => {
    expect(iframeCsp(false)).toContain("default-src 'none'");
    expect(iframeCsp(true)).toContain('img-src https: data:');
  });
});
