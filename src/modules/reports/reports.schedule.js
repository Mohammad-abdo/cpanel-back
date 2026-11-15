/** Minimal UTC cron support: "M H DOM MON DOW" where each field is a number or "*". */
const FIELD = /^(\*|\d{1,2})$/;

export function parseCron(expr) {
  const parts = String(expr).trim().split(/\s+/);
  if (parts.length !== 5 || !parts.every((p) => FIELD.test(p))) return null;
  const [m, h, dom, mon, dow] = parts.map((p) => (p === '*' ? null : Number(p)));
  if ((m !== null && m > 59) || (h !== null && h > 23) || (dom !== null && (dom < 1 || dom > 31))) return null;
  if ((mon !== null && (mon < 1 || mon > 12)) || (dow !== null && dow > 6)) return null;
  if (m === null || h === null) return null; // a schedule must pin the time of day
  return { m, h, dom, mon, dow };
}

/** Most recent scheduled instant at or before `at` (UTC), or null within 400 days. */
export function lastDue(expr, at) {
  const c = parseCron(expr);
  if (!c) return null;
  for (let back = 0; back <= 400; back += 1) {
    const day = new Date(Date.UTC(at.getUTCFullYear(), at.getUTCMonth(), at.getUTCDate() - back, c.h, c.m, 0));
    if (day.getTime() > at.getTime()) continue;
    if (c.dom !== null && day.getUTCDate() !== c.dom) continue;
    if (c.mon !== null && day.getUTCMonth() + 1 !== c.mon) continue;
    if (c.dow !== null && day.getUTCDay() !== c.dow) continue;
    return day;
  }
  return null;
}

/** Report period that ends at the start of the UTC day of the due instant. */
export function periodFor(period, due) {
  const dayStart = new Date(Date.UTC(due.getUTCFullYear(), due.getUTCMonth(), due.getUTCDate()));
  if (period === 'monthly') {
    const to = new Date(Date.UTC(due.getUTCFullYear(), due.getUTCMonth(), 1));
    return { from: new Date(Date.UTC(to.getUTCFullYear(), to.getUTCMonth() - 1, 1)), to };
  }
  return { from: new Date(dayStart.getTime() - 7 * 86400000), to: dayStart };
}
