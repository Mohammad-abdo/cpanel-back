export PGPASSWORD="$NT_PASS"
if [ "$MODE" = isolated ]; then createdb -h 127.0.0.1 -U "$USER_" "$DB" 2>"$ERR" || { echo "__NT_ERR__create_failed:$(head -c 200 "$ERR" | tr '\n' ' ')" >&2; exit 2; }; fi
gunzip -c "$DIR/in.gz" | psql -h 127.0.0.1 -U "$USER_" -d "$DB" -v ON_ERROR_STOP=1 -q 2>"$ERR" >/dev/null || { echo "__NT_ERR__restore_failed:$(head -c 300 "$ERR" | tr '\n' ' ')" >&2; exit 2; }
TABLES=$(psql -h 127.0.0.1 -U "$USER_" -d "$DB" -At -c "select count(*) from information_schema.tables where table_schema not in ('pg_catalog','information_schema')" 2>/dev/null || echo -1)
