CLI=$(command -v mysql || command -v mariadb) || { echo "__NT_ERR__mysql_not_found" >&2; exit 2; }
if [ "$MODE" = isolated ]; then "$CLI" --defaults-extra-file="$WORK/cfg" -e "CREATE DATABASE \`$DB\`" 2>"$ERR" || { echo "__NT_ERR__create_failed:$(head -c 200 "$ERR" | tr '\n' ' ')" >&2; exit 2; }; fi
gunzip -c "$DIR/in.gz" | "$CLI" --defaults-extra-file="$WORK/cfg" "$DB" 2>"$ERR" || { echo "__NT_ERR__restore_failed:$(head -c 300 "$ERR" | tr '\n' ' ')" >&2; exit 2; }
TABLES=$("$CLI" --defaults-extra-file="$WORK/cfg" -N -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='$DB'" 2>/dev/null || echo -1)
