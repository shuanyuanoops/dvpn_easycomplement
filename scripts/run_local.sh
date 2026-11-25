#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p bin

go build -o bin/relay ./cmd/relay
go build -o bin/client ./cmd/client
go build -o bin/sink ./cmd/sink
go build -o bin/audit ./cmd/audit

KE=$(openssl rand -hex 32)
KM=$(openssl rand -hex 32)
KX=$(openssl rand -hex 32)

pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT

./bin/sink -listen 127.0.0.1:17004 -duration 3s -name sink -receipt /tmp/dvpn_sink.json > /tmp/dvpn_sink.log 2>&1 & pids+=($!)
./bin/relay -id exit-0 -role exit -name exit-0 -key "$KX" -listen 127.0.0.1:17003 -dest 127.0.0.1:17004 -receipt /tmp/dvpn_exit.json > /tmp/dvpn_exit.log 2>&1 & pids+=($!)
./bin/relay -id middle-0 -role middle -name middle-0 -key "$KM" -listen 127.0.0.1:17002 -next-id exit-0 -next-addr 127.0.0.1:17003 -receipt /tmp/dvpn_middle.json > /tmp/dvpn_middle.log 2>&1 & pids+=($!)
./bin/relay -id entry-0 -role entry -name entry-0 -key "$KE" -listen 127.0.0.1:17001 -next-id middle-0 -next-addr 127.0.0.1:17002 -receipt /tmp/dvpn_entry.json > /tmp/dvpn_entry.log 2>&1 & pids+=($!)

sleep 0.5
./bin/client -entry 127.0.0.1:17001 -path entry-0,middle-0,exit-0 -k-entry "$KE" -k-middle "$KM" -k-exit "$KX" -n 4000 -rate 4000 -name client -receipt /tmp/dvpn_client.json
sleep 2.6
kill -TERM "${pids[@]}" 2>/dev/null || true
sleep 0.3

echo '--- sink ---'; cat /tmp/dvpn_sink.log
echo '--- entry ---'; cat /tmp/dvpn_entry.log
echo '--- middle ---'; cat /tmp/dvpn_middle.log
echo '--- exit ---'; cat /tmp/dvpn_exit.log
echo '--- audit ---'
./bin/audit -receipts /tmp/dvpn_client.json,/tmp/dvpn_entry.json,/tmp/dvpn_middle.json,/tmp/dvpn_exit.json,/tmp/dvpn_sink.json
