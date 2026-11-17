set -u
umask 077
D=$(mktemp -d /tmp/nt-bk.XXXXXXXX) || exit 2
echo "NT_DIR=$D"
