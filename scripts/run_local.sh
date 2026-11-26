#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p bin

go build -o bin/relay ./cmd/relay
go build -o bin/client ./cmd/client
go build -o bin/sink ./cmd/sink
go build -o bin/audit ./cmd/audit

pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT

rm -f /tmp/dvpn_entry.id /tmp/dvpn_middle.id /tmp/dvpn_exit.id
./bin/sink -listen 127.0.0.1:17004 -duration 3s -name sink -receipt /tmp/dvpn_sink.json > /tmp/dvpn_sink.log 2>&1 & pids+=($!)
./bin/relay -id exit-0 -role exit -name exit-0 -listen 127.0.0.1:17003 -dest 127.0.0.1:17004 -identity-out /tmp/dvpn_exit.id -receipt /tmp/dvpn_exit.json > /tmp/dvpn_exit.log 2>&1 & pids+=($!)
./bin/relay -id middle-0 -role middle -name middle-0 -listen 127.0.0.1:17002 -next-id exit-0 -next-addr 127.0.0.1:17003 -identity-out /tmp/dvpn_middle.id -receipt /tmp/dvpn_middle.json > /tmp/dvpn_middle.log 2>&1 & pids+=($!)
./bin/relay -id entry-0 -role entry -name entry-0 -listen 127.0.0.1:17001 -next-id middle-0 -next-addr 127.0.0.1:17002 -identity-out /tmp/dvpn_entry.id -receipt /tmp/dvpn_entry.json > /tmp/dvpn_entry.log 2>&1 & pids+=($!)

for f in /tmp/dvpn_entry.id /tmp/dvpn_middle.id /tmp/dvpn_exit.id; do
  for i in $(seq 1 30); do [ -s "$f" ] && break; sleep 0.1; done
done
./bin/client -entry 127.0.0.1:17001 -path entry-0,middle-0,exit-0 \
  -id-entry /tmp/dvpn_entry.id \
  -id-middle /tmp/dvpn_middle.id \
  -id-exit /tmp/dvpn_exit.id \
  -n 4000 -rate 4000 -name client -receipt /tmp/dvpn_client.json
sleep 2.6
kill -TERM "${pids[@]}" 2>/dev/null || true
sleep 0.3

echo '--- sink ---'; cat /tmp/dvpn_sink.log
echo '--- entry ---'; cat /tmp/dvpn_entry.log
echo '--- middle ---'; cat /tmp/dvpn_middle.log
echo '--- exit ---'; cat /tmp/dvpn_exit.log
echo '--- audit ---'
./bin/audit -receipts /tmp/dvpn_client.json,/tmp/dvpn_entry.json,/tmp/dvpn_middle.json,/tmp/dvpn_exit.json,/tmp/dvpn_sink.json
