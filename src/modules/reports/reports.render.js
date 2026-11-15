import { AppError } from '../../common/errors/app-error.js';

const FORMULA = /^[=+\-@\t\r]/;
const cell = (value) => {
  let s = value === null || value === undefined ? '' : String(value);
  if (FORMULA.test(s)) s = `'${s}`; // neutralize spreadsheet formula injection
  return `"${s.replace(/"/g, '""')}"`;
};

/** Every renderer consumes the same report object, so figures cannot drift between formats. */
export const csvRenderer = {
  format: 'csv',
  contentType: 'text/csv; charset=utf-8',
  extension: 'csv',
  render(report) {
    const rows = [['section', 'key', 'label', 'value', 'unit', 'source_events']];
    rows.push(['meta', 'type', report.type, '', '', '']);
    rows.push(['meta', 'period', `${report.period.from ?? ''} to ${report.period.to ?? ''}`, '', '', '']);
    for (const m of report.metrics) {
      rows.push(['metric', m.key, m.label, m.value === null ? 'N/A' : m.value, m.unit, m.lineageTotal ?? 0]);
    }
    for (const b of report.breakdowns) {
      for (const r of b.rows) rows.push([b.key, r.key, r.label, r.value, 'count', r.lineageTotal ?? 0]);
    }
    return rows.map((r) => r.map(cell).join(',')).join('\n');
  },
};

export const jsonRenderer = {
  format: 'json',
  contentType: 'application/json',
  extension: 'json',
  render: (report) => JSON.stringify(report),
};

/**
 * Renderer registry. PDF and Excel need new dependencies, so they are REQUIRES DECISION: requesting them
 * returns 501 until a renderer implementing { format, contentType, extension, render(report) } is registered.
 */
export function createRendererRegistry(extra = []) {
  const map = new Map([csvRenderer, jsonRenderer, ...extra].map((r) => [r.format, r]));
  return {
    formats: () => [...map.keys()],
    get(format) {
      const r = map.get(format);
      if (!r) {
        throw new AppError(501, 'FORMAT_REQUIRES_DECISION', `${format} output requires an approved renderer dependency`);
      }
      return r;
    },
  };
}
