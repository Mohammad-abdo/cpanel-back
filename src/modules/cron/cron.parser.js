/**
 * Tiny in-house 5-field cron parser (no dependency). Minute resolution, UTC.
 * Fields: minute(0-59) hour(0-23) day-of-month(1-31) month(1-12|JAN-DEC) day-of-week(0-7|SUN-SAT, 7 = 0).
 * Supports `*`, `a`, `a-b`, `a-b/n`, `*` + `/n`, `a/n` (a to max), comma lists, and the macros @hourly @daily @midnight
 * @weekly @monthly @yearly @annually. Day-of-month and day-of-week follow Vixie semantics: if both are restricted a
 * day matches when EITHER matches. Because the finest unit is one minute, the minimum interval is 60 seconds.
 */

const MONTHS = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
const DOWS = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'];
const MACROS = { '@hourly': '0 * * * *', '@daily': '0 0 * * *', '@midnight': '0 0 * * *', '@weekly': '0 0 * * 0', '@monthly': '0 0 1 * *', '@yearly': '0 0 1 1 *', '@annually': '0 0 1 1 *' };

const SPECS = [
  { name: 'minute', min: 0, max: 59 },
  { name: 'hour', min: 0, max: 23 },
  { name: 'day-of-month', min: 1, max: 31 },
  { name: 'month', min: 1, max: 12, names: MONTHS, offset: 1 },
  { name: 'day-of-week', min: 0, max: 7, names: DOWS, offset: 0 },
];

export class CronParseError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CronParseError';
  }
}

function value(tok, spec) {
  if (/^\d+$/.test(tok)) {
    const n = Number(tok);
    if (n < spec.min || n > spec.max) throw new CronParseError(`${spec.name} value ${n} out of range ${spec.min}-${spec.max}`);
    return n;
  }
  if (spec.names) {
    const i = spec.names.indexOf(tok.toUpperCase());
    if (i >= 0) return i + spec.offset;
  }
  throw new CronParseError(`Invalid ${spec.name} value "${tok}"`);
}

function parseField(text, spec) {
  const set = new Set();
  if (text === '') throw new CronParseError(`Empty ${spec.name} field`);
  for (const part of text.split(',')) {
    if (part === '') throw new CronParseError(`Empty list item in ${spec.name}`);
    const [range, stepText, extra] = part.split('/');
    if (extra !== undefined) throw new CronParseError(`Invalid step in ${spec.name}`);
    let step = 1;
    if (stepText !== undefined) {
      if (!/^\d+$/.test(stepText) || Number(stepText) < 1) throw new CronParseError(`Invalid step "${stepText}" in ${spec.name}`);
      step = Number(stepText);
    }
    let lo;
    let hi;
    if (range === '*') {
      lo = spec.min;
      hi = spec.name === 'day-of-week' ? 6 : spec.max;
    } else if (range.includes('-')) {
      const [a, b, more] = range.split('-');
      if (more !== undefined || a === '' || b === '') throw new CronParseError(`Invalid range "${range}" in ${spec.name}`);
      lo = value(a, spec);
      hi = value(b, spec);
      if (lo > hi) throw new CronParseError(`Range start after end in ${spec.name}`);
    } else {
      lo = value(range, spec);
      hi = stepText !== undefined ? (spec.name === 'day-of-week' ? 6 : spec.max) : lo;
    }
    for (let v = lo; v <= hi; v += step) set.add(spec.name === 'day-of-week' && v === 7 ? 0 : v);
  }
  return set;
}

/** Parses an expression. Throws CronParseError. */
export function parseCron(expr) {
  if (typeof expr !== 'string') throw new CronParseError('Schedule must be a string');
  let text = expr.trim().replace(/\s+/g, ' ');
  if (text.startsWith('@')) {
    if (!MACROS[text.toLowerCase()]) throw new CronParseError(`Unsupported macro ${text}`);
    text = MACROS[text.toLowerCase()];
  }
  const f = text.split(' ');
  if (f.length !== 5) throw new CronParseError('A cron schedule needs exactly 5 fields (minute hour day-of-month month day-of-week)');
  const [minute, hour, dom, month, dow] = f.map((t, i) => parseField(t, SPECS[i]));
  return { minute, hour, dom, month, dow, domAny: f[2] === '*', dowAny: f[4] === '*' };
}

export function isValidCron(expr) {
  try {
    parseCron(expr);
    return true;
  } catch {
    return false;
  }
}

function dayMatches(p, y, m, d) {
  const dowV = new Date(Date.UTC(y, m, d)).getUTCDay();
  const domOk = p.dom.has(d);
  const dowOk = p.dow.has(dowV);
  if (!p.domAny && !p.dowAny) return domOk || dowOk;
  if (!p.domAny) return domOk;
  if (!p.dowAny) return dowOk;
  return true;
}

/** First run strictly after `from` (a Date), in UTC. Returns null if none exists within 8 years (e.g. 31 FEB). */
export function nextRun(expr, from = new Date()) {
  const p = typeof expr === 'string' ? parseCron(expr) : expr;
  const t = new Date(from.getTime());
  t.setUTCSeconds(0, 0);
  t.setUTCMinutes(t.getUTCMinutes() + 1);
  const limit = t.getUTCFullYear() + 8;
  const minutes = [...p.minute].sort((a, b) => a - b);
  const hours = [...p.hour].sort((a, b) => a - b);
  let y = t.getUTCFullYear();
  let mo = t.getUTCMonth();
  let d = t.getUTCDate();
  let first = true;
  while (y <= limit) {
    if (p.month.has(mo + 1)) {
      const dim = new Date(Date.UTC(y, mo + 1, 0)).getUTCDate();
      for (; d <= dim; d++) {
        if (!dayMatches(p, y, mo, d)) {
          first = false;
          continue;
        }
        const sameDay = first && d === t.getUTCDate() && mo === t.getUTCMonth() && y === t.getUTCFullYear();
        for (const h of hours) {
          if (sameDay && h < t.getUTCHours()) continue;
          for (const mi of minutes) {
            if (sameDay && h === t.getUTCHours() && mi < t.getUTCMinutes()) continue;
            return new Date(Date.UTC(y, mo, d, h, mi, 0, 0));
          }
        }
        first = false;
      }
    }
    first = false;
    d = 1;
    mo += 1;
    if (mo > 11) {
      mo = 0;
      y += 1;
    }
  }
  return null;
}

/** The next `count` runs after `from`. */
export function nextRuns(expr, from, count = 5) {
  const out = [];
  let at = from;
  for (let i = 0; i < count; i++) {
    const n = nextRun(expr, at);
    if (!n) break;
    out.push(n);
    at = n;
  }
  return out;
}
