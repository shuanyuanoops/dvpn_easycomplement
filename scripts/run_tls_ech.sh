#!/usr/bin/env bash
# TLS 1.3 ingress: client --TLS--> tlsgate --UDP--> entry -> middle -> exit.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p bin

go build -o bin/relay ./cmd/relay
go build -o bin/client ./cmd/client
go build -o bin/sink ./cmd/sink
go build -o bin/audit ./cmd/audit
go build -o bin/tlsgate ./cmd/tlsgate

pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT

rm -f /tmp/dvpn_ech_entry.id /tmp/dvpn_ech_middle.id /tmp/dvpn_ech_exit.id

./bin/sink -listen 127.0.0.1:17004 -duration 3s -name sink -receipt /tmp/dvpn_ech_sink.json > /tmp/dvpn_ech_sink.log 2>&1 & pids+=($!)
./bin/relay -id exit-0 -role exit -name exit-0 -listen 127.0.0.1:17003 -dest 127.0.0.1:17004 -identity-out /tmp/dvpn_ech_exit.id -receipt /tmp/dvpn_ech_exit.json > /tmp/dvpn_ech_exit.log 2>&1 & pids+=($!)
./bin/relay -id middle-0 -role middle -name middle-0 -listen 127.0.0.1:17002 -next-id exit-0 -next-addr 127.0.0.1:17003 -identity-out /tmp/dvpn_ech_middle.id -receipt /tmp/dvpn_ech_middle.json > /tmp/dvpn_ech_middle.log 2>&1 & pids+=($!)
./bin/relay -id entry-0 -role entry -name entry-0 -listen 127.0.0.1:17001 -next-id middle-0 -next-addr 127.0.0.1:17002 -identity-out /tmp/dvpn_ech_entry.id -receipt /tmp/dvpn_ech_entry.json > /tmp/dvpn_ech_entry.log 2>&1 & pids+=($!)

./bin/tlsgate -listen 127.0.0.1:17443 -entry 127.0.0.1:17001 -frame 1024 -tls-name dvpn.local -ech -ech-out /tmp/dvpn_ech.bin > /tmp/dvpn_ech_gate.log 2>&1 & pids+=($!)

for f in /tmp/dvpn_ech_entry.id /tmp/dvpn_ech_middle.id /tmp/dvpn_ech_exit.id; do
  for i in $(seq 1 30); do [ -s "$f" ] && break; sleep 0.1; done
done
for i in $(seq 1 50); do
  [ -s /tmp/dvpn_ech.bin ] && break
  sleep 0.1
done
if [ ! -s /tmp/dvpn_ech.bin ]; then
  echo "ERROR: ECH config not written"; cat /tmp/dvpn_ech_gate.log; exit 1
fi


./bin/client -tls -tls-gate 127.0.0.1:17443 -tls-name dvpn.local -tls-insecure -ech-config /tmp/dvpn_ech.bin \
  -entry 127.0.0.1:17001 -path entry-0,middle-0,exit-0 \
  -id-entry /tmp/dvpn_ech_entry.id \
  -id-middle /tmp/dvpn_ech_middle.id \
  -id-exit /tmp/dvpn_ech_exit.id \
  -n 4000 -rate 4000 -name client -receipt /tmp/dvpn_ech_client.json

sleep 2.6
kill -TERM "${pids[@]}" 2>/dev/null || true
sleep 0.3

echo '--- gate ---'; cat /tmp/dvpn_ech_gate.log
echo '--- sink ---'; cat /tmp/dvpn_ech_sink.log
echo '--- entry ---'; cat /tmp/dvpn_ech_entry.log
echo '--- audit ---'
./bin/audit -receipts /tmp/dvpn_ech_client.json,/tmp/dvpn_ech_entry.json,/tmp/dvpn_ech_middle.json,/tmp/dvpn_ech_exit.json,/tmp/dvpn_ech_sink.json
