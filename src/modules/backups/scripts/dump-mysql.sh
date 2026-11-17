BIN=$(command -v mysqldump || command -v mariadb-dump) || { echo "__NT_ERR__mysqldump_not_found" >&2; exit 2; }
set +e
"$BIN" --defaults-extra-file="$WORK/cfg" --single-transaction --quick --routines --triggers --events --hex-blob --no-tablespaces "$DB" 2>"$ERR" | gzip -c | head -c "$LIMIT" >"$OUT"
RC=("${PIPESTATUS[@]}"); set -e
FAILED=0; if [ "${RC[0]}" -ne 0 ] || [ "${RC[1]}" -ne 0 ]; then FAILED=1; fi
