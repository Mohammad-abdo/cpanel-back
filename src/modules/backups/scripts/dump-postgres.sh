command -v pg_dump >/dev/null || { echo "__NT_ERR__pg_dump_not_found" >&2; exit 2; }
set +e
PGPASSWORD="$NT_PASS" pg_dump -h 127.0.0.1 -U "$USER_" -d "$DB" -F p --no-owner --no-acl 2>"$ERR" | gzip -c | head -c "$LIMIT" >"$OUT"
RC=("${PIPESTATUS[@]}"); set -e
FAILED=0; if [ "${RC[0]}" -ne 0 ] || [ "${RC[1]}" -ne 0 ]; then FAILED=1; fi
