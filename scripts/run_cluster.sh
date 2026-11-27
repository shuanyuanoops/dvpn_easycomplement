#!/usr/bin/env bash
# Local demo cluster: registry -> controller random assignment -> routed relays.
#
# Topology:
#   entries  127.0.0.1:17101 entry-0, 127.0.0.1:17102 entry-1
#   middles  127.0.0.1:17103 middle-0, 127.0.0.1:17104 middle-1
#   exits    127.0.0.1:17105 exit-0, 127.0.0.1:17106 exit-1 (-> sink 17110)
#   sink     127.0.0.1:17110
#   controller 127.0.0.1:18000
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p bin

SINK_ADDR=127.0.0.1:17110
CONTROLLER_ADDR=127.0.0.1:18000
ROUTES=/tmp/dvpn_routes.json
RELAYS=/tmp/dvpn_relays.json
CONTROLLER_LOG=/tmp/dvpn_controller.log

go build -o bin/relay ./cmd/relay
go build -o bin/linkaudit ./cmd/linkaudit
go build -o bin/client ./cmd/client
go build -o bin/sink ./cmd/sink
go build -o bin/audit ./cmd/audit
go build -o bin/controller ./cmd/controller

pids=()
relay_pids=()
sink_pid=""
cleanup() {
  local p
  for p in "${pids[@]:-}"; do
    kill -TERM "$p" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT

check_ports() {
  if ! command -v ss >/dev/null 2>&1; then
    echo "note: ss not found, skipping port pre-check" >&2
    return 0
  fi
  local udp tcp
  udp=$(ss -H -lun 2>/dev/null | awk '{print $4}' || true)
  tcp=$(ss -H -ltn 2>/dev/null | awk '{print $4}' || true)
  if grep -qE ':(1710[1-6]|17110)$' <<<"$udp" || grep -qE ':18000$' <<<"$tcp"; then
    echo "ERROR: cluster ports already in use (udp 17101-17106/17110, tcp 18000)" >&2
    echo "       inspect with: ss -lunpt | grep -E '1710[1-6]|17110|18000'" >&2
    echo "       stop the stale processes from an earlier run first" >&2
    exit 1
  fi
}

wait_file() {
  local f=$1 i ok=0
  for i in $(seq 1 100); do
    if [ -s "$f" ]; then ok=1; break; fi
    sleep 0.05
  done
  if [ "$ok" != 1 ]; then
    echo "ERROR: $f was not written" >&2
    exit 1
  fi
}

wait_tcp() {
  local host=$1 port=$2 i
  for i in $(seq 1 100); do
    if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
      return 0
    fi
    sleep 0.05
  done
  return 1
}

check_ports

rm -f /tmp/dvpn_entry-*.id /tmp/dvpn_middle-*.id /tmp/dvpn_exit-*.id
rm -f /tmp/dvpn_entry-*.json /tmp/dvpn_middle-*.json /tmp/dvpn_exit-*.json
rm -f /tmp/dvpn_entry-*.log /tmp/dvpn_middle-*.log /tmp/dvpn_exit-*.log
rm -f /tmp/dvpn_client.json /tmp/dvpn_client.log /tmp/dvpn_sink.json /tmp/dvpn_sink.log
rm -f "$ROUTES" "$RELAYS" "$CONTROLLER_LOG" /tmp/dvpn_audit.log

cat >"$ROUTES" <<'EOF'
{
  "entry-0": "127.0.0.1:17101",
  "entry-1": "127.0.0.1:17102",
  "middle-0": "127.0.0.1:17103",
  "middle-1": "127.0.0.1:17104",
  "exit-0": "127.0.0.1:17105",
  "exit-1": "127.0.0.1:17106"
}
EOF

cat >"$RELAYS" <<'EOF'
{
  "relays": [
    {"id": "entry-0",  "role": "entry",  "addr": "127.0.0.1:17101", "identity": "/tmp/dvpn_entry-0.id", "as": "AS65001"},
    {"id": "entry-1",  "role": "entry",  "addr": "127.0.0.1:17102", "identity": "/tmp/dvpn_entry-1.id", "as": "AS65002"},
    {"id": "middle-0", "role": "middle", "addr": "127.0.0.1:17103", "identity": "/tmp/dvpn_middle-0.id", "as": "AS65003"},
    {"id": "middle-1", "role": "middle", "addr": "127.0.0.1:17104", "identity": "/tmp/dvpn_middle-1.id", "as": "AS65004"},
    {"id": "exit-0",   "role": "exit",   "addr": "127.0.0.1:17105", "identity": "/tmp/dvpn_exit-0.id", "as": "AS65005"},
    {"id": "exit-1",   "role": "exit",   "addr": "127.0.0.1:17106", "identity": "/tmp/dvpn_exit-1.id", "as": "AS65006"}
  ]
}
EOF

# The sink must outlive the client and then exit on its own so it writes a
# receipt; 6s covers startup + a 1s client burst with plenty of margin.
./bin/sink -listen "$SINK_ADDR" -duration 6s -name sink -receipt /tmp/dvpn_sink.json > /tmp/dvpn_sink.log 2>&1 &
sink_pid=$!
pids+=("$sink_pid")

for i in 0 1; do
  id="entry-$i"
  ./bin/relay -id "$id" -role entry -name "$id" -listen "127.0.0.1:$((17101 + i))" \
    -routes "$ROUTES" -identity-out "/tmp/dvpn_$id.id" -receipt "/tmp/dvpn_$id.json" \
    -control-addr "127.0.0.1:$((17201 + i))" \
    > "/tmp/dvpn_$id.log" 2>&1 &
  relay_pids+=($!)
done
for i in 0 1; do
  id="middle-$i"
  ./bin/relay -id "$id" -role middle -name "$id" -listen "127.0.0.1:$((17103 + i))" \
    -routes "$ROUTES" -identity-out "/tmp/dvpn_$id.id" -receipt "/tmp/dvpn_$id.json" \
    -control-addr "127.0.0.1:$((17203 + i))" \
    > "/tmp/dvpn_$id.log" 2>&1 &
  relay_pids+=($!)
done
for i in 0 1; do
  id="exit-$i"
  ./bin/relay -id "$id" -role exit -name "$id" -listen "127.0.0.1:$((17105 + i))" \
    -dest "$SINK_ADDR" -identity-out "/tmp/dvpn_$id.id" -receipt "/tmp/dvpn_$id.json" \
    -control-addr "127.0.0.1:$((17205 + i))" \
    > "/tmp/dvpn_$id.log" 2>&1 &
  relay_pids+=($!)
done
pids+=("${relay_pids[@]}")

./bin/controller -relays "$RELAYS" -listen "$CONTROLLER_ADDR" > "$CONTROLLER_LOG" 2>&1 &
pids+=($!)

for i in 0 1; do
  wait_file "/tmp/dvpn_entry-$i.id"
  wait_file "/tmp/dvpn_middle-$i.id"
  wait_file "/tmp/dvpn_exit-$i.id"
done
if ! wait_tcp 127.0.0.1 18000; then
  echo "ERROR: controller did not come up on $CONTROLLER_ADDR" >&2
  cat "$CONTROLLER_LOG" >&2 || true
  exit 1
fi

if ! ./bin/client -controller "http://$CONTROLLER_ADDR" -n 4000 -rate 4000 \
  -name client -receipt /tmp/dvpn_client.json > /tmp/dvpn_client.log 2>&1; then
  echo "ERROR: client failed" >&2
  cat /tmp/dvpn_client.log >&2 || true
  echo '--- controller ---' >&2
  cat "$CONTROLLER_LOG" >&2 || true
  exit 1
fi
sleep 1

if ! ./bin/linkaudit -relays "entry-0=http://127.0.0.1:17201,entry-1=http://127.0.0.1:17202,middle-0=http://127.0.0.1:17203,middle-1=http://127.0.0.1:17204,exit-0=http://127.0.0.1:17205,exit-1=http://127.0.0.1:17206" > /tmp/dvpn_linkaudit.log 2>&1; then
  echo "ERROR: linkaudit failed" >&2
  cat /tmp/dvpn_linkaudit.log >&2 || true
  exit 1
fi
cat /tmp/dvpn_linkaudit.log

line=$(grep -E '^assign ' "$CONTROLLER_LOG" | tail -1 || true)
if [ -z "$line" ]; then
  echo "ERROR: controller logged no assignment" >&2
  cat "$CONTROLLER_LOG" >&2 || true
  exit 1
fi
entry_id=$(sed -E 's/.*entry=([^ ]+).*/\1/' <<<"$line")
middle_id=$(sed -E 's/.*middle=([^ ]+).*/\1/' <<<"$line")
exit_id=$(sed -E 's/.*exit=([^ ]+).*/\1/' <<<"$line")

# Stop the relays so they write receipts, then let the sink finish its window
# so its receipt covers the whole run.
for p in "${relay_pids[@]}"; do
  kill -TERM "$p" 2>/dev/null || true
done
for p in "${relay_pids[@]}"; do
  wait "$p" 2>/dev/null || true
done
wait "$sink_pid" 2>/dev/null || true
sleep 0.2

for f in /tmp/dvpn_client.json "/tmp/dvpn_$entry_id.json" "/tmp/dvpn_$middle_id.json" "/tmp/dvpn_$exit_id.json" /tmp/dvpn_sink.json; do
  if [ ! -s "$f" ]; then
    echo "ERROR: missing receipt $f" >&2
    exit 1
  fi
done

echo "--- controller assignment ---"
echo "$line"
echo "--- client ---"
cat /tmp/dvpn_client.log
echo "--- entry ($entry_id) ---"
cat "/tmp/dvpn_$entry_id.log"
echo "--- middle ($middle_id) ---"
cat "/tmp/dvpn_$middle_id.log"
echo "--- exit ($exit_id) ---"
cat "/tmp/dvpn_$exit_id.log"
echo "--- sink ---"
cat /tmp/dvpn_sink.log
echo "--- audit ---"
./bin/audit -receipts "/tmp/dvpn_client.json,/tmp/dvpn_$entry_id.json,/tmp/dvpn_$middle_id.json,/tmp/dvpn_$exit_id.json,/tmp/dvpn_sink.json" | tee /tmp/dvpn_audit.log

if ! grep -q 'sent=4000 replies=4000 loss=0.00%' /tmp/dvpn_client.log; then
  echo "FAIL: expected client sent=4000 replies=4000 loss=0.00%" >&2
  exit 1
fi
if grep -q 'MISMATCH' /tmp/dvpn_audit.log; then
  echo "FAIL: audit reported a mismatch" >&2
  exit 1
fi
echo "OK: $entry_id -> $middle_id -> $exit_id, 4000/4000 replies, audit clean"
