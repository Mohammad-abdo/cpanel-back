import { describe, expect, it } from 'vitest';
import { generateTotp, generateTotpSecret, verifyTotp } from '../src/common/crypto/totp.js';

describe('totp', () => {
  it('generates and verifies a code for the same secret', () => {
    const secret = generateTotpSecret();
    const now = Date.UTC(2026, 10, 15, 12, 0, 0);
    const code = generateTotp(secret, { now });
    expect(code).toMatch(/^\d{6}$/);
    expect(verifyTotp(secret, code, { now })).toBe(true);
  });

  it('rejects wrong codes', () => {
    const secret = generateTotpSecret();
    const now = Date.UTC(2026, 10, 15, 12, 0, 0);
    expect(verifyTotp(secret, '000000', { now })).toBe(false);
  });
});
