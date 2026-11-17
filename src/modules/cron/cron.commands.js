/** Cron command allowlist, remote script builder and output redaction (TASK-048). Pure functions, unit tested. */

/** Reviewed fixed commands. A custom command is anything else and needs an approval (cron.custom.command). */
export const CRON_COMMANDS = Object.freeze({
  'laravel.schedule': { label: 'Laravel scheduler (php artisan schedule:run)', command: 'php artisan schedule:run' },
  'laravel.queue.restart': { label: 'Laravel queue restart signal', command: 'php artisan queue:restart' },
  'npm.cron': { label: 'npm run cron (script defined in package.json)', command: 'npm run cron --if-present' },
  'npm.backup': { label: 'npm run backup (script defined in package.json)', command: 'npm run backup --if-present' },
  'pm2.save': { label: 'pm2 save', command: 'pm2 save' },
});

export const MIN_TIMEOUT_SEC = 5;
export const MAX_TIMEOUT_SEC = 3600;
export const OUTPUT_TAIL_CAP = 4000;

const WORKDIR_RE = /^\/[A-Za-z0-9._/+-]+$/;
export const isSafeWorkDir = (p) => typeof p === 'string' && p.length <= 190 && WORKDIR_RE.test(p) && !p.includes('..') && !/^\/(etc|root|proc|sys|boot|dev|bin|sbin|usr|lib)(\/|$)/.test(p) && !/(^|\/)\.ssh(\/|$)/.test(p);

/** Custom commands: single line, bounded, no NUL. Everything else is the approver's judgement. */
export function isSafeCustomCommand(cmd) {
  return typeof cmd === 'string' && cmd.trim().length > 0 && cmd.length <= 500 && !/[\0\r\n]/.test(cmd);
}

const shq = (a) => `'${String(a).replace(/'/g, `'\\''`)}'`;

/** Remote script: cd into the project dir, run the command under `timeout`, merge stderr. Exit 124 means timeout. */
export function buildCronScript({ workDir, command, timeoutSec }) {
  if (!isSafeWorkDir(workDir)) throw new Error('unsafe workDir');
  const t = Math.min(MAX_TIMEOUT_SEC, Math.max(MIN_TIMEOUT_SEC, Math.floor(Number(timeoutSec) || 300)));
  return [
    `cd ${shq(workDir)} 2>/dev/null || { echo "workDir not found: ${workDir}"; exit 97; }`,
    `timeout --signal=TERM --kill-after=10 ${t} sh -c ${shq(command)} 2>&1`,
    'echo "NT_EXIT:$?"',
  ].join('\n');
}

/** Resolves the command text for a job row. */
export function commandFor(job) {
  if (job.commandKey) {
    const c = CRON_COMMANDS[job.commandKey];
    if (!c) throw new Error(`Unknown command key ${job.commandKey}`);
    return c.command;
  }
  if (!isSafeCustomCommand(job.customCommand)) throw new Error('Invalid custom command');
  return job.customCommand;
}

const PATTERNS = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g, '[REDACTED PRIVATE KEY]'],
  [/(\b(?:authorization)\b\s*[:=]\s*)(?:bearer|basic|token)?\s*\S+/gi, '$1[REDACTED]'],
  [/\bbearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, 'Bearer [REDACTED]'],
  [/(\b[\w.-]*(?:pass(?:word|wd)?|secret|token|api[-_]?key|access[-_]?key|private[-_]?key|credentials?)[\w.-]*\b\s*[=:]\s*)("[^"]*"|'[^']*'|\S+)/gi, '$1[REDACTED]'],
  [/(--(?:password|passwd|token|secret|api-key)(?:=|\s+))\S+/gi, '$1[REDACTED]'],
  [/(\s-p)(?!\s)\S{3,}/g, '$1[REDACTED]'],
  [/([a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:)[^\s@/]+@/gi, '$1[REDACTED]@'],
  [/\b(?:ghp|gho|ghs|github_pat|glpat|xox[abpr]|sk|pk|AKIA)[-_A-Za-z0-9]{12,}/g, '[REDACTED TOKEN]'],
];

/** Redacts secret-looking material, strips ANSI, and keeps only the last `cap` characters. */
export function redactOutput(text, cap = OUTPUT_TAIL_CAP) {
  let out = String(text ?? '').replace(/\u001b\[[0-9;]*[A-Za-z]/g, '').replace(/\r/g, '');
  for (const [re, rep] of PATTERNS) out = out.replace(re, rep);
  return out.length > cap ? `...${out.slice(-cap)}` : out;
}

/** Splits the script output into the command output and the exit code marker. */
export function parseCronOutput(stdout) {
  const m = /NT_EXIT:(\d+)\s*$/.exec(String(stdout ?? ''));
  const body = m ? String(stdout).slice(0, m.index) : String(stdout ?? '');
  return { exitCode: m ? Number(m[1]) : null, output: body };
}
