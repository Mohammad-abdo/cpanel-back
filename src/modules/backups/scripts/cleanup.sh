set -u
case "$1" in /tmp/nt-bk.[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9]) rm -rf -- "$1";; *) exit 2;; esac
