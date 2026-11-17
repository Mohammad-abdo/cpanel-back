/**
 * Live database browse over SSH (MySQL / Postgres / MongoDB) via CLI clients.
 * Identifiers are validated before shell quoting — never interpolate raw user input.
 */

/** List databases via mongosh (JSON array of names). Password never goes on argv when auth is set. */
export function mongoListDatabasesCmd(auth = null) {
  const evalJs = `JSON.stringify(db.adminCommand({ listDatabases: 1 }).databases.map(d => d.name))`;
  if (auth?.username) {
    const user = assertSafeDbUser(auth.username);
    const pass = String(auth.password ?? '');
    return [
      'ERRFILE=$(mktemp)',
      `OUT=$(mongosh --quiet --username ${shQuote(user)} --password ${shQuote(pass)} --eval ${shQuote(evalJs)} 2>>"$ERRFILE"); EC=$?`,
      'printf "%s" "$OUT"',
      'if [ "$EC" -ne 0 ] || [ -z "$OUT" ]; then printf "\\n__NT_ERR__%s" "$(tr "\\n" "|" <"$ERRFILE" | cut -c1-400)" >&2; fi',
      'rm -f "$ERRFILE"',
      '[ -n "$OUT" ]',
    ].join('; ');
  }
  return [
    'ERRFILE=$(mktemp)',
    `OUT=$(mongosh --quiet --eval ${shQuote(evalJs)} 2>>"$ERRFILE"); EC=$?`,
    'printf "%s" "$OUT"',
    'if [ "$EC" -ne 0 ] || [ -z "$OUT" ]; then printf "\\n__NT_ERR__%s" "$(tr "\\n" "|" <"$ERRFILE" | cut -c1-400)" >&2; fi',
    'rm -f "$ERRFILE"',
    '[ -n "$OUT" ]',
  ].join('; ');
}

/** List collection names in one database. */
export function mongoListCollectionsCmd(db, auth = null) {
  const dbName = assertSafeDbName(db);
  const evalJs = `JSON.stringify(db.getSiblingDB(${JSON.stringify(dbName)}).getCollectionNames())`;
  if (auth?.username) {
    const user = assertSafeDbUser(auth.username);
    const pass = String(auth.password ?? '');
    return [
      'ERRFILE=$(mktemp)',
      `OUT=$(mongosh --quiet --username ${shQuote(user)} --password ${shQuote(pass)} --eval ${shQuote(evalJs)} 2>>"$ERRFILE"); EC=$?`,
      'printf "%s" "$OUT"',
      'if [ "$EC" -ne 0 ] || [ -z "$OUT" ]; then printf "\\n__NT_ERR__%s" "$(tr "\\n" "|" <"$ERRFILE" | cut -c1-400)" >&2; fi',
      'rm -f "$ERRFILE"',
      '[ -n "$OUT" ]',
    ].join('; ');
  }
  return [
    'ERRFILE=$(mktemp)',
    `OUT=$(mongosh --quiet --eval ${shQuote(evalJs)} 2>>"$ERRFILE"); EC=$?`,
    'printf "%s" "$OUT"',
    'if [ "$EC" -ne 0 ] || [ -z "$OUT" ]; then printf "\\n__NT_ERR__%s" "$(tr "\\n" "|" <"$ERRFILE" | cut -c1-400)" >&2; fi',
    'rm -f "$ERRFILE"',
    '[ -n "$OUT" ]',
  ].join('; ');
}

/** Sample documents from one collection (JSON array). No arbitrary query strings. */
export function mongoSampleCmd(db, collection, limit = 50, auth = null) {
  const dbName = assertSafeDbName(db);
  const coll = assertSafeIdent(collection, 'collection');
  const lim = Math.min(Math.max(Number(limit) || 50, 1), 200);
  const evalJs = `JSON.stringify(db.getSiblingDB(${JSON.stringify(dbName)}).getCollection(${JSON.stringify(coll)}).find().limit(${lim}).toArray())`;
  if (auth?.username) {
    const user = assertSafeDbUser(auth.username);
    const pass = String(auth.password ?? '');
    return [
      'ERRFILE=$(mktemp)',
      `OUT=$(mongosh --quiet --username ${shQuote(user)} --password ${shQuote(pass)} --eval ${shQuote(evalJs)} 2>>"$ERRFILE"); EC=$?`,
      'printf "%s" "$OUT"',
      'if [ "$EC" -ne 0 ] || [ -z "$OUT" ]; then printf "\\n__NT_ERR__%s" "$(tr "\\n" "|" <"$ERRFILE" | cut -c1-400)" >&2; fi',
      'rm -f "$ERRFILE"',
      '[ -n "$OUT" ]',
    ].join('; ');
  }
  return [
    'ERRFILE=$(mktemp)',
    `OUT=$(mongosh --quiet --eval ${shQuote(evalJs)} 2>>"$ERRFILE"); EC=$?`,
    'printf "%s" "$OUT"',
    'if [ "$EC" -ne 0 ] || [ -z "$OUT" ]; then printf "\\n__NT_ERR__%s" "$(tr "\\n" "|" <"$ERRFILE" | cut -c1-400)" >&2; fi',
    'rm -f "$ERRFILE"',
    '[ -n "$OUT" ]',
  ].join('; ');
}

export const SAFE_ENGINE = new Set(['mysql', 'postgres', 'mongodb']);
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

const MYSQL_GRANT_ALLOW = new Set(['SELECT', 'INSERT', 'UPDATE', 'DELETE']);

/** Escape a MySQL string literal (password / host). Never use for identifiers. */
export function mysqlStringLiteral(value) {
  return `'${String(value).replace(/[\0\b\t\x1a\\']/g, (c) => {
    if (c === '\0') return '\\0';
    if (c === '\b') return '\\b';
    if (c === '\t') return '\\t';
    if (c === '\x1a') return '\\Z';
    if (c === '\\') return '\\\\';
    return "\\'";
  })}'`;
}

/** TASK-022: CREATE DATABASE with safe identifier quoting. */
export function createDatabaseSql(dbName) {
  assertSafeDbName(dbName);
  return `CREATE DATABASE IF NOT EXISTS ${mysqlIdent(dbName)} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`;
}

/** TASK-022: scoped user + GRANT without GRANT OPTION. Password is embedded as a literal for one remote run. */
export function createScopedUserSql({ username, password, host = '127.0.0.1', dbName, grants }) {
  assertSafeDbName(dbName);
  assertSafeDbUser(username);
  if (typeof host !== 'string' || !/^[A-Za-z0-9._%-]{1,64}$/.test(host)) {
    throw Object.assign(new Error('Invalid database host'), { code: 'DB_HOST_INVALID' });
  }
  const list = Array.isArray(grants) ? grants : [];
  if (!list.length || list.some((g) => !MYSQL_GRANT_ALLOW.has(g))) {
    throw Object.assign(new Error('Invalid privilege set'), { code: 'DB_GRANT_INVALID' });
  }
  const userSpec = `${mysqlIdent(username)}@${mysqlStringLiteral(host)}`;
  return [
    `CREATE USER IF NOT EXISTS ${userSpec} IDENTIFIED BY ${mysqlStringLiteral(password)}`,
    `GRANT ${list.join(', ')} ON ${mysqlIdent(dbName)}.* TO ${userSpec}`,
    'FLUSH PRIVILEGES',
  ].join('; ');
}

export function dropDatabaseSql(dbName) {
  assertSafeDbName(dbName);
  return `DROP DATABASE IF EXISTS ${mysqlIdent(dbName)}`;
}

/**
 * Run DDL/admin SQL over mysql CLI. Succeeds on exit code 0 even when stdout is empty
 * (unlike browse queries which require a result set).
 */
export function mysqlAdminCmd(sql, auth) {
  if (!auth?.username) {
    throw Object.assign(new Error('MySQL admin login required'), { code: 'DB_LOGIN_REQUIRED' });
  }
  const q = shQuote(sql);
  const user = assertSafeDbUser(auth.username);
  const pass = String(auth.password ?? '');
  return [
    'ERRFILE=$(mktemp)',
    'CFG=$(mktemp)',
    'chmod 600 "$CFG"',
    `printf '%s\\n' '[client]' 'user=${user}' >"$CFG"`,
    `printf 'password=%s\\n' ${shQuote(pass)} >>"$CFG"`,
    `mysql --defaults-extra-file="$CFG" --batch --raw --default-character-set=utf8mb4 -e ${q} 2>"$ERRFILE"; EC=$?`,
    'if [ "$EC" -ne 0 ]; then printf "__NT_ERR__%s" "$(tr "\\n" "|" <"$ERRFILE" | cut -c1-400)" >&2; fi',
    'rm -f "$ERRFILE" "$CFG"',
    'test "$EC" -eq 0',
  ].join('; ');
}

function writeMysqlCnf(auth) {
  const user = assertSafeDbUser(auth.username);
  const pass = String(auth.password ?? '');
  return [
    'CFG=$(mktemp)',
    'chmod 600 "$CFG"',
    `printf '%s\\n' '[client]' 'user=${user}' >"$CFG"`,
    `printf 'password=%s\\n' ${shQuote(pass)} >>"$CFG"`,
  ].join('; ');
}

/**
 * Dump one schema or all databases to OUT path on the remote host.
 * Requires auth for MySQL; Postgres uses auth or falls back to peer/sudo when auth is null.
 */
export function buildDumpCommand(engine, { db = null, auth = null, outPath }) {
  if (!outPath || typeof outPath !== 'string' || !outPath.startsWith('/tmp/')) {
    throw Object.assign(new Error('Invalid dump path'), { code: 'DB_DUMP_PATH' });
  }
  const out = shQuote(outPath);
  if (engine === 'mysql') {
    if (!auth?.username) throw Object.assign(new Error('MySQL dump requires a saved DB login'), { code: 'DB_LOGIN_REQUIRED' });
    const target = db ? shQuote(assertSafeDbName(db)) : '--all-databases';
    return [
      writeMysqlCnf(auth),
      'ERRFILE=$(mktemp)',
      `mysqldump --defaults-extra-file="$CFG" --single-transaction --routines --triggers --events --hex-blob ${target} >${out} 2>"$ERRFILE"`,
      'EC=$?',
      'rm -f "$CFG"',
      'if [ "$EC" -ne 0 ]; then printf "__NT_ERR__%s" "$(tr "\\n" "|" <"$ERRFILE" | cut -c1-400)" >&2; rm -f "$ERRFILE" ' + out + '; exit 1; fi',
      'rm -f "$ERRFILE"',
      `test -s ${out}`,
    ].join('; ');
  }
  if (engine === 'postgres') {
    if (auth?.username) {
      const user = assertSafeDbUser(auth.username);
      const pass = String(auth.password ?? '');
      if (db) {
        return [
          `export PGPASSWORD=${shQuote(pass)}`,
          `pg_dump -U ${shQuote(user)} -d ${shQuote(assertSafeDbName(db))} -F p --no-owner --no-acl >${out}`,
          'EC=$?',
          'unset PGPASSWORD',
          `test "$EC" -eq 0 && test -s ${out}`,
        ].join('; ');
      }
      return [
        `export PGPASSWORD=${shQuote(pass)}`,
        `pg_dumpall -U ${shQuote(user)} --no-role-passwords >${out}`,
        'EC=$?',
        'unset PGPASSWORD',
        `test "$EC" -eq 0 && test -s ${out}`,
      ].join('; ');
    }
    if (db) {
      return `sudo -n -u postgres pg_dump -d ${shQuote(assertSafeDbName(db))} -F p --no-owner --no-acl >${out}`;
    }
    return `sudo -n -u postgres pg_dumpall --no-role-passwords >${out}`;
  }
  throw Object.assign(new Error('Unsupported engine'), { code: 'DB_ENGINE_INVALID' });
}

/** Restore a SQL dump file into one schema (optional) or the whole server. */
export function buildRestoreCommand(engine, { db = null, auth = null, inPath }) {
  if (!inPath || typeof inPath !== 'string' || !inPath.startsWith('/tmp/')) {
    throw Object.assign(new Error('Invalid restore path'), { code: 'DB_RESTORE_PATH' });
  }
  const inn = shQuote(inPath);
  if (engine === 'mysql') {
    if (!auth?.username) throw Object.assign(new Error('MySQL restore requires a saved DB login'), { code: 'DB_LOGIN_REQUIRED' });
    const dbArg = db ? ` ${shQuote(assertSafeDbName(db))}` : '';
    return [
      writeMysqlCnf(auth),
      'ERRFILE=$(mktemp)',
      `mysql --defaults-extra-file="$CFG"${dbArg} <${inn} 2>"$ERRFILE"`,
      'EC=$?',
      'rm -f "$CFG"',
      'if [ "$EC" -ne 0 ]; then printf "__NT_ERR__%s" "$(tr "\\n" "|" <"$ERRFILE" | cut -c1-400)" >&2; rm -f "$ERRFILE"; exit 1; fi',
      'rm -f "$ERRFILE"',
    ].join('; ');
  }
  if (engine === 'postgres') {
    if (auth?.username) {
      const user = assertSafeDbUser(auth.username);
      const pass = String(auth.password ?? '');
      const dbName = db ? assertSafeDbName(db) : 'postgres';
      return [
        `export PGPASSWORD=${shQuote(pass)}`,
        `psql -U ${shQuote(user)} -d ${shQuote(dbName)} -v ON_ERROR_STOP=1 -f ${inn}`,
        'EC=$?',
        'unset PGPASSWORD',
        'test "$EC" -eq 0',
      ].join('; ');
    }
    const dbName = db ? assertSafeDbName(db) : 'postgres';
    return `sudo -n -u postgres psql -d ${shQuote(dbName)} -v ON_ERROR_STOP=1 -f ${inn}`;
  }
  throw Object.assign(new Error('Unsupported engine'), { code: 'DB_ENGINE_INVALID' });
}
