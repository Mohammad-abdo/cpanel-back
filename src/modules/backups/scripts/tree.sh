[ -d "$ROOT" ] || { echo "__NT_ERR__not_a_directory" >&2; exit 2; }
REAL=$(realpath -e -- "$ROOT") || { echo "__NT_ERR__not_a_directory" >&2; exit 2; }
[ "$REAL" = "$ROOT" ] || { echo "__NT_ERR__root_is_symlink_or_unnormalized" >&2; exit 2; }
set +e
tar -C "$ROOT" @EXCLUDES@ -cf - . 2>"$ERR" | gzip -c | head -c "$LIMIT" >"$OUT"
RC=("${PIPESTATUS[@]}"); set -e
FAILED=0; if [ "${RC[0]}" -gt 1 ] || [ "${RC[1]}" -ne 0 ]; then FAILED=1; fi
