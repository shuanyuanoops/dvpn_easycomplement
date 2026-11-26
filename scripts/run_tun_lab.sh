#!/usr/bin/env bash
# Two-namespace TUN demo: client TUN -> UDP onion -> exit TUN -> local HTTP.
# Requires user namespaces (unshare -Urnm) and /dev/net/tun. No root needed.
set -euo pipefail

if [[ "${DVPN_TUN_LAB:-}" != "1" ]]; then
	exec unshare -Urnm env DVPN_TUN_LAB=1 bash "$0" "$@"
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TMP=/tmp/dvpn-tun-lab
rm -rf "$TMP"
mkdir -p "$TMP"

CLIENT_NS_PID=""
PIDS=()
cleanup() {
	for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
	[[ -n "$CLIENT_NS_PID" ]] && kill "$CLIENT_NS_PID" 2>/dev/null || true
	ip link del veth-h 2>/dev/null || true
}
trap cleanup EXIT

echo "== build =="
go build -o "$TMP/client" ./cmd/client
go build -o "$TMP/relay" ./cmd/relay

echo "== client netns + veth =="
unshare -n sleep 300 &
CLIENT_NS_PID=$!
sleep 0.3
ip link add veth-c type veth peer name veth-h
ip link set veth-c netns "$CLIENT_NS_PID"
ip addr add 10.200.0.1/24 dev veth-h
ip link set veth-h up
nsenter -t "$CLIENT_NS_PID" -n ip link set lo up
nsenter -t "$CLIENT_NS_PID" -n ip addr add 10.200.0.2/24 dev veth-c
nsenter -t "$CLIENT_NS_PID" -n ip link set veth-c up

cat > "$TMP/routes.json" <<'EOF'
{"entry-0":"10.200.0.1:17101","middle-0":"127.0.0.1:17102","exit-0":"127.0.0.1:17103"}
EOF

ip link set lo up

echo "== relays =="
"$TMP/relay" -id entry-0 -role entry -listen 10.200.0.1:17101 \
	-routes "$TMP/routes.json" -identity-out "$TMP/entry.id" \
	> "$TMP/entry.log" 2>&1 &
PIDS+=($!)
"$TMP/relay" -id middle-0 -role middle -listen 127.0.0.1:17102 \
	-routes "$TMP/routes.json" -identity-out "$TMP/middle.id" \
	> "$TMP/middle.log" 2>&1 &
PIDS+=($!)
"$TMP/relay" -id exit-0 -role exit -listen 127.0.0.1:17103 \
	-routes "$TMP/routes.json" -identity-out "$TMP/exit.id" \
	-tun -tun-name dvpn1 -tun-ip 10.99.0.1/24 -tun-mtu 800 \
	> "$TMP/exit.log" 2>&1 &
PIDS+=($!)

for f in entry.id middle.id exit.id; do
	for _ in $(seq 1 50); do [[ -s "$TMP/$f" ]] && break; sleep 0.1; done
	[[ -s "$TMP/$f" ]] || { echo "missing $f"; cat "$TMP"/*.log; exit 1; }
done
for _ in $(seq 1 50); do ip link show dvpn1 >/dev/null 2>&1 && break; sleep 0.1; done
ip link show dvpn1 >/dev/null 2>&1 || { echo "exit TUN not created"; cat "$TMP/exit.log"; exit 1; }

echo "== http server on exit TUN =="
python3 -m http.server 8080 --bind 10.99.0.1 --directory "$ROOT" \
	> "$TMP/http.log" 2>&1 &
PIDS+=($!)

echo "== client in client netns =="
nsenter -t "$CLIENT_NS_PID" -n "$TMP/client" \
	-tun -tun-name dvpn0 -tun-ip 10.99.0.2/24 -tun-mtu 800 \
	-entry 10.200.0.1:17101 -path entry-0,middle-0,exit-0 \
	-id-entry "$TMP/entry.id" -id-middle "$TMP/middle.id" -id-exit "$TMP/exit.id" \
	> "$TMP/client.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 50); do nsenter -t "$CLIENT_NS_PID" -n ip link show dvpn0 >/dev/null 2>&1 && break; sleep 0.1; done
sleep 0.5

echo "== curl through TUN =="
set +e
OUT=$(nsenter -t "$CLIENT_NS_PID" -n curl -sS --max-time 5 http://10.99.0.1:8080/ 2>&1)
RC=$?
set -e
if [[ $RC -ne 0 ]]; then
	echo "curl failed: $OUT"
	echo "--- client ---"; cat "$TMP/client.log"
	echo "--- exit ---"; cat "$TMP/exit.log"
	echo "--- entry ---"; cat "$TMP/entry.log"
	exit 1
fi
echo "$OUT" | head -5
echo "OK: TUN packet path works (client 10.99.0.2 -> exit 10.99.0.1)"
