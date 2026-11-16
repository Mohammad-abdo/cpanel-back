/**
 * Live database browse over SSH (MySQL / Postgres) via CLI clients.
 * Identifiers are validated before shell quoting — never interpolate raw user input.
 */

export const SAFE_ENGINE = new Set(['mysql', 'postgres']);
export const SAFE_IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
export const SAFE_DB_NAME = /^[A-Za-z0-9_-]{1,64}$/;
export const SAFE_DB_USER = /^[A-Za-z0-9_./@-]{1,64}$/;

const SYSTEM_MYSQL = new Set(['information_schema', 'mysql', 'performance_schema', 'sys']);
const SYSTEM_PG = new Set(['template0', 'template1', 'postgres']);

export function assertSafeIdent(name, label = 'identifier') {
  if (typeof name !== 'string' || !SAFE_IDENT.test(name)) {
    throw Object.assign(new Error(`Invalid ${label}`), { code: 'DB_IDENT_INVALID' });
  }
  return name;
}

export function assertSafeDbName(name) {
  if (typeof name !== 'string' || !SAFE_DB_NAME.test(name)) {
    throw Object.assign(new Error('Invalid database name'), { code: 'DB_NAME_INVALID' });
  }
  return name;
}

export function assertSafeDbUser(name) {
  if (typeof name !== 'string' || !SAFE_DB_USER.test(name)) {
    throw Object.assign(new Error('Invalid database username'), { code: 'DB_USER_INVALID' });
  }
  return name;
}

function shQuote(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}

function mysqlIdent(name) {
  return `\`${String(name).replace(/`/g, '``')}\``;
}

function pgIdent(name) {
  return `"${String(name).replace(/"/g, '""')}"`;
}

/**
 * MySQL/MariaDB CLI. When auth is provided, uses a temp defaults file (password never
 * appears as a mysql argv flag). Otherwise falls back to sudo/debian.cnf probes.
 */
export function mysqlCmd(sql, db = null, auth = null) {
  const q = shQuote(sql);
  const dbArg = db ? ` ${shQuote(assertSafeDbName(db))}` : '';
  const flags = `--batch --raw --default-character-set=utf8mb4${dbArg} -e ${q}`;
  if (auth?.username) {
    const user = assertSafeDbUser(auth.username);
    const pass = String(auth.password ?? '');
    return [
      'ERRFILE=$(mktemp)',
      'CFG=$(mktemp)',
      'chmod 600 "$CFG"',
      `printf '%s\\n' '[client]' 'user=${user}' >"$CFG"`,
      `printf 'password=%s\\n' ${shQuote(pass)} >>"$CFG"`,
      `OUT=$(mysql --defaults-extra-file="$CFG" ${flags} 2>>"$ERRFILE"); EC=$?`,
      'if [ "$EC" -ne 0 ] || [ -z "$OUT" ]; then OUT=""; fi',
      'printf "%s" "$OUT"',
      'if [ -z "$OUT" ]; then printf "\\n__NT_ERR__%s" "$(tr "\\n" "|" <"$ERRFILE" | cut -c1-400)" >&2; fi',
      'rm -f "$ERRFILE" "$CFG"',
      '[ -n "$OUT" ]',
    ].join('; ');
  }
  return [
    'ERRFILE=$(mktemp)',
    'CFG=$(mktemp)',
    'OUT=""',
    'EC=1',
    'if [ -r /etc/mysql/debian.cnf ]; then cp /etc/mysql/debian.cnf "$CFG"; fi',
    'if [ ! -s "$CFG" ] && sudo -n test -r /etc/mysql/debian.cnf 2>/dev/null; then sudo -n cat /etc/mysql/debian.cnf >"$CFG" 2>/dev/null; fi',
    `OUT=$(sudo -n mysql ${flags} 2>>"$ERRFILE"); EC=$?`,
    'if [ "$EC" -ne 0 ] || [ -z "$OUT" ]; then OUT=$(sudo -n mysql --protocol=socket ' + flags + ' 2>>"$ERRFILE"); EC=$?; fi',
    'if { [ "$EC" -ne 0 ] || [ -z "$OUT" ]; } && [ -s "$CFG" ]; then OUT=$(mysql --defaults-extra-file="$CFG" ' + flags + ' 2>>"$ERRFILE"); EC=$?; fi',
    'if { [ "$EC" -ne 0 ] || [ -z "$OUT" ]; } && [ -s "$CFG" ]; then OUT=$(sudo -n mysql --defaults-extra-file="$CFG" ' + flags + ' 2>>"$ERRFILE"); EC=$?; fi',
    'if [ "$EC" -ne 0 ] || [ -z "$OUT" ]; then OUT=""; fi',
    'printf "%s" "$OUT"',
    'if [ -z "$OUT" ]; then printf "\\n__NT_ERR__%s" "$(tr "\\n" "|" <"$ERRFILE" | cut -c1-400)" >&2; fi',
    'rm -f "$ERRFILE" "$CFG"',
    '[ -n "$OUT" ]',
  ].join('; ');
}

export function postgresCmd(sql, auth = null) {
  const q = shQuote(sql);
  if (auth?.username) {
    const user = assertSafeDbUser(auth.username);
    const pass = String(auth.password ?? '');
    return [
      `export PGPASSWORD=${shQuote(pass)}`,
      `OUT=$(psql -U ${shQuote(user)} -v ON_ERROR_STOP=1 -P pager=off -F $'\\t' -A -c ${q} 2>/tmp/nt-pg-err.$$)`,
      'EC=$?',
      'unset PGPASSWORD',
      'printf "%s" "$OUT"',
      'if [ "$EC" -ne 0 ] || [ -z "$OUT" ]; then printf "\\n__NT_ERR__%s" "$(tr "\\n" "|" </tmp/nt-pg-err.$$ | cut -c1-400)" >&2; rm -f /tmp/nt-pg-err.$$; false; else rm -f /tmp/nt-pg-err.$$; true; fi',
    ].join('; ');
  }
  return (
    `(sudo -n -u postgres psql -v ON_ERROR_STOP=1 -P pager=off -F $'\\t' -A -c ${q} 2>/dev/null` +
    ` || psql -U postgres -v ON_ERROR_STOP=1 -P pager=off -F $'\\t' -A -c ${q} 2>/dev/null` +
    ` || psql -v ON_ERROR_STOP=1 -P pager=off -F $'\\t' -A -c ${q} 2>/dev/null)`
  );
}

/** Parse mysql --batch TSV (first row = headers). */
export function parseMysqlBatch(text) {
  const lines = String(text ?? '')
    .split('\n')
    .map((l) => l.replace(/\r$/, ''))
    .filter((l) => l.length > 0);
  if (!lines.length) return { columns: [], rows: [] };
  const columns = lines[0].split('\t');
  const rows = lines.slice(1).map((line) => {
    const cells = line.split('\t');
    const obj = {};
    columns.forEach((c, i) => {
      obj[c] = cells[i] === undefined || cells[i] === 'NULL' ? null : cells[i];
    });
    return obj;
  });
  return { columns, rows };
}

/** Parse psql -A -F tab aligned output (includes header when not -t). */
export function parsePsqlAligned(text) {
  const lines = String(text ?? '')
    .split('\n')
    .map((l) => l.replace(/\r$/, ''))
    .filter((l) => l.length > 0 && l !== 'NULL');
  if (!lines.length) return { columns: [], rows: [] };
  // Without -t, first line is header; row count line "(N rows)" may appear at end for some modes — strip it.
  const body = lines.filter((l) => !/^\(\d+ rows?\)$/.test(l));
  if (!body.length) return { columns: [], rows: [] };
  const columns = body[0].split('\t');
  const rows = body.slice(1).map((line) => {
    const cells = line.split('\t');
    const obj = {};
    columns.forEach((c, i) => {
      obj[c] = cells[i] === undefined || cells[i] === '' ? null : cells[i];
    });
    return obj;
  });
  return { columns, rows };
}

export function listSchemasSql(engine) {
  if (engine === 'mysql') return 'SHOW DATABASES';
  return `SELECT datname AS name FROM pg_database WHERE datistemplate = false ORDER BY 1`;
}

export function listTablesSql(engine, db) {
  assertSafeDbName(db);
  if (engine === 'mysql') {
    return `SELECT TABLE_NAME AS name, TABLE_TYPE AS type, ENGINE AS engine, TABLE_ROWS AS approx_rows
FROM information_schema.TABLES WHERE TABLE_SCHEMA = '${db}' ORDER BY TABLE_NAME`;
  }
  return `SELECT tablename AS name, 'BASE TABLE' AS type FROM pg_tables WHERE schemaname = 'public'
UNION ALL
SELECT viewname AS name, 'VIEW' AS type FROM pg_views WHERE schemaname = 'public'
ORDER BY 1`;
}

/** For postgres, connect to the target database. */
export function postgresCmdInDb(db, sql, auth = null) {
  assertSafeDbName(db);
  const q = shQuote(sql);
  const dbq = shQuote(db);
  if (auth?.username) {
    const user = assertSafeDbUser(auth.username);
    const pass = String(auth.password ?? '');
    return [
      `export PGPASSWORD=${shQuote(pass)}`,
      `OUT=$(psql -U ${shQuote(user)} -d ${dbq} -v ON_ERROR_STOP=1 -P pager=off -F $'\\t' -A -c ${q} 2>/tmp/nt-pg-err.$$)`,
      'EC=$?',
      'unset PGPASSWORD',
      'printf "%s" "$OUT"',
      'if [ "$EC" -ne 0 ] || [ -z "$OUT" ]; then printf "\\n__NT_ERR__%s" "$(tr "\\n" "|" </tmp/nt-pg-err.$$ | cut -c1-400)" >&2; rm -f /tmp/nt-pg-err.$$; false; else rm -f /tmp/nt-pg-err.$$; true; fi',
    ].join('; ');
  }
  return (
    `(sudo -n -u postgres psql -d ${dbq} -v ON_ERROR_STOP=1 -P pager=off -F $'\\t' -A -c ${q} 2>/dev/null` +
    ` || psql -U postgres -d ${dbq} -v ON_ERROR_STOP=1 -P pager=off -F $'\\t' -A -c ${q} 2>/dev/null)`
  );
}

export function describeTableSql(engine, db, table) {
  assertSafeDbName(db);
  assertSafeIdent(table, 'table');
  if (engine === 'mysql') {
    return `SELECT COLUMN_NAME AS name, COLUMN_TYPE AS type, IS_NULLABLE AS nullable, COLUMN_KEY AS \`key\`, COLUMN_DEFAULT AS \`default\`, EXTRA AS extra
FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '${db}' AND TABLE_NAME = '${table}' ORDER BY ORDINAL_POSITION`;
  }
  return `SELECT a.attname AS name, pg_catalog.format_type(a.atttypid, a.atttypmod) AS type,
CASE WHEN a.attnotnull THEN 'NO' ELSE 'YES' END AS nullable
FROM pg_attribute a
JOIN pg_class c ON a.attrelid = c.oid
JOIN pg_namespace n ON c.relnamespace = n.oid
WHERE n.nspname = 'public' AND c.relname = '${table}' AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY a.attnum`;
}

export function selectRowsSql(engine, db, table, limit = 50, offset = 0) {
  assertSafeDbName(db);
  assertSafeIdent(table, 'table');
  const lim = Math.min(Math.max(Number(limit) || 50, 1), 200);
  const off = Math.min(Math.max(Number(offset) || 0, 0), 100000);
  if (engine === 'mysql') {
    // Database is selected via mysql CLI db argument; quote table only.
    return `SELECT * FROM ${mysqlIdent(table)} LIMIT ${lim} OFFSET ${off}`;
  }
  return `SELECT * FROM ${pgIdent(table)} LIMIT ${lim} OFFSET ${off}`;
}

export function filterSchemaNames(engine, names) {
  const sys = engine === 'mysql' ? SYSTEM_MYSQL : SYSTEM_PG;
  return names.filter((n) => n && !sys.has(n));
}

export function isMutatingSql(sql) {
  const head = String(sql ?? '')
    .replace(/^\s*\/\*[\s\S]*?\*\//, '')
    .replace(/^\s*--[^\n]*/gm, '')
    .trim()
    .slice(0, 32)
    .toUpperCase();
  return /^(INSERT|UPDATE|DELETE|REPLACE|DROP|ALTER|CREATE|TRUNCATE|GRANT|REVOKE|RENAME|CALL|LOAD|IMPORT|COPY)\b/.test(head);
}
