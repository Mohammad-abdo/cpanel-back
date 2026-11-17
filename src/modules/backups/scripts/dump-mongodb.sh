command -v mongodump >/dev/null || { echo "__NT_ERR__mongodump_not_found" >&2; exit 2; }
set +e
mongodump --config "$WORK/cfg" --username "$USER_" --authenticationDatabase admin --db "$DB" --archive --gzip 2>"$ERR" | head -c "$LIMIT" >"$OUT"
RC=("${PIPESTATUS[@]}"); set -e
FAILED=0; if [ "${RC[0]}" -ne 0 ]; then FAILED=1; fi
