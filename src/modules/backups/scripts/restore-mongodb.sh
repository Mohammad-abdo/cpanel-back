DROP=""; [ "$MODE" = inplace ] && DROP="--drop"
mongorestore --config "$WORK/cfg" --username "$USER_" --authenticationDatabase admin --archive="$DIR/in.gz" --gzip --nsFrom "$SRC.*" --nsTo "$DB.*" $DROP 2>"$ERR" || { echo "__NT_ERR__restore_failed:$(head -c 300 "$ERR" | tr '\n' ' ')" >&2; exit 2; }
TABLES=-1
