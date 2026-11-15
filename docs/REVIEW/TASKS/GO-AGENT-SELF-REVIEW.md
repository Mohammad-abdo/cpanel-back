# GO-AGENT Self Review

SELF_REVIEW only; not independent review. Status: NOT_VERIFIED (code never compiled).

## Checked by manual re-read

- Imports and variable use re-read per file; no unused import or variable found.
- Platform split: parse.go and tests are platform neutral; collector_linux.go (`//go:build linux`) holds /proc and syscall.Statfs; collector_other.go is a stub.
- Standard library only; go.mod unchanged (module github.com/nodeteam/ubuntu-agent, go 1.22).
- Read-only: no listener, no server-supplied command execution; only fixed-argument `systemctl` and `pm2 jlist` with timeouts, no shell.
- No stale replay: failed snapshots are dropped, each tick collects fresh data.
- Credentials written 0600 via temp file and rename; key redacted in String(); never logged.
- Retry: bounded (4 attempts), exponential backoff with jitter, 401/403/4xx not retried.
- The old scaffold OperationEnvelope/validateEnvelope code was removed (listener-less design); this replaces historical scaffold work.

## Risks

- Compile errors are possible since no Go toolchain was available.
- Response envelope assumed `{data: ...}` (matches apps/api agents.controller.js); bare objects are also accepted.
- `ReadOnlyPaths=/` with ProtectSystem=strict and User= needs verification on Ubuntu.
- systemctl state/manager mapping is heuristic (apache2/httpd, nginx); others reported as systemd.
- PM2 apps are visible only for the agent user's PM2 home; production PM2 may run under another user.
- Report `state` string length limits on the server were not checked.
