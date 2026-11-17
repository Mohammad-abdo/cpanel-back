SZ=$(stat -c %s "$OUT" 2>/dev/null || echo 0)
if [ "$SZ" -gt "$CAP" ]; then echo "__NT_ERR__size_cap_exceeded" >&2; exit 3; fi
if [ "$FAILED" = 1 ]; then echo "__NT_ERR__dump_failed:$(head -c 300 "$ERR" 2>/dev/null | tr '\n' ' ')" >&2; exit 2; fi
if [ "$SZ" -lt 1 ]; then echo "__NT_ERR__empty_output" >&2; exit 4; fi
SHA=$(sha256sum "$OUT" | cut -d' ' -f1)
OK=1
echo "NT_OUT=$OUT"; echo "NT_SHA256=$SHA"; echo "NT_SIZE=$SZ"
