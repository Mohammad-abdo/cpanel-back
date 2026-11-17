CLI=$(command -v mysql || command -v mariadb) || exit 2
"$CLI" --defaults-extra-file="$WORK/cfg" -e "DROP DATABASE IF EXISTS \`$DB\`"
