set -u
umask 077
IFS= read -r NT_PASS || NT_PASS=''
WORK=$(mktemp -d /tmp/nt-bk.XXXXXXXX) || { echo "__NT_ERR__mktemp_failed" >&2; exit 2; }
OK=0
cleanup() { rm -f "$WORK/cfg"; if [ "$OK" != 1 ]; then rm -rf "$WORK"; fi; }
trap cleanup EXIT
