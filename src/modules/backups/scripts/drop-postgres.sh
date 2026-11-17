PGPASSWORD="$NT_PASS" dropdb -h 127.0.0.1 -U "$USER_" --if-exists "$DB"
