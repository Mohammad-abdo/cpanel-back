# GO-AGENT Test Record

Scope: agents/ubuntu-agent (read-only Ubuntu agent: enroll, run, collector, client, config).

## Result: NOT_RUN

Compile and tests were not executed. `go` is not on PATH and not present at C:\Program Files\Go\bin on this Windows host. No result is claimed.

## Commands that must be run (on a machine with Go 1.22+)

```
cd agents/ubuntu-agent
gofmt -l .
go vet ./...
go test ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/nodeteam-agent-linux-amd64 ./cmd/agent
```

## Tests written (unexecuted)

- config: save/load round trip, 0600 mode (skipped on Windows), incomplete credentials rejected, String() redacts key.
- collector: parsing of /proc/stat, meminfo, loadavg, uptime, net tcp/udp LISTEN, systemctl output, pm2 jlist; service/port caps; JSON omits unknown optional keys.
- client (httptest): enroll success with {data} envelope, `Authorization: Agent <id>.<key>` header, retry on 5xx then success, bounded retries, 401 not retried, 4xx not retried, context cancel, TLS option validation.

## Must still be verified

1. Compiles and vets cleanly on linux/amd64 and on Windows (stub collector).
2. Real Linux run: /proc parsing against a live host, systemctl and pm2 invocation, statfs on `/`.
3. End-to-end against the real API: enroll then report accepted (HTTP 202), schema accepted with no unknown keys.
4. Hardened systemd unit starts under ProtectSystem=strict and can read credentials.
5. mTLS flags against a real CA/client certificate.
6. Unauthorized (revoked) handling against a real revoked agent.

Not production verified.

## Update — field length clamp
`capServices` now clamps service name to 120 and state to 40 runes to match the API validator (an over-length value would reject the whole report). Still NOT_RUN: Go is not installed here, so compile and tests remain unexecuted.
