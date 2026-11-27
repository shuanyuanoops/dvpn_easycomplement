#!/usr/bin/env bash
# Exit NAT demo: client TUN -> onion -> exit TUN -> host forwarding/NAT -> WAN.
# The "WAN" is a separate netns with 203.0.113.1/24 and an HTTP server; no real
# Internet is required, but the packet path and MASQUERADE are real.
set -euo pipefail

if [[ "${DVPN_NAT:-}" != "1" ]]; then
	exec unshare -Urnm env DVPN_NAT=1 bash "$(cd "$(dirname "$0")" && pwd)/$(basename "$0")" "$@"
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TMP=/tmp/dvpn-nat
rm -rf "$TMP"
mkdir -p "$TMP" bin

CLIENT_NS=""
WAN_NS=""
CLIENT_PID=""
PIDS=()

dump_logs() {
	local f
	for f in "$TMP"/*.log; do
		[[ -s "$f" ]] || continue
		echo "--- $(basename "$f") ---" >&2
		cat "$f" >&2 || true
	done
}

fail() { echo "FAIL: $*" >&2; dump_logs; exit 1; }

cleanup() {
	local p i alive
	for p in "${PIDS[@]:-}"; do
		[[ "$p" == "$CLIENT_PID" ]] && continue
		kill -TERM "$p" 2>/dev/null || true
	done
	[[ -n "$CLIENT_PID" ]] && kill -KILL "$CLIENT_PID" 2>/dev/null || true
	for i in $(seq 1 30); do
		alive=0
		for p in "${PIDS[@]:-}"; do
			[[ "$p" == "$CLIENT_PID" ]] && continue
			kill -0 "$p" 2>/dev/null && alive=1
		done
		[[ "$alive" -eq 0 ]] && break
		sleep 0.05
	done
	for p in "${PIDS[@]:-}"; do kill -KILL "$p" 2>/dev/null || true; done
	for p in "${PIDS[@]:-}"; do wait "$p" 2>/dev/null || true; done
	for p in "$CLIENT_NS" "$WAN_NS"; do
		[[ -n "$p" ]] && kill -TERM "$p" 2>/dev/null || true
		[[ -n "$p" ]] && wait "$p" 2>/dev/null || true
	done
	ip link del veth-c 2>/dev/null || true
	ip link del veth-wan 2>/dev/null || true
}
trap cleanup EXIT

wait_file() {
	local f=$1 i
	for i in $(seq 1 100); do [[ -s "$f" ]] && return 0; sleep 0.1; done
	return 1
}
wait_log() {
	local f=$1 pat=$2 i
	for i in $(seq 1 100); do
		[[ -f "$f" ]] && grep -qF -- "$pat" "$f" && return 0
		sleep 0.1
	done
	return 1
}
wait_tcp() {
	local h=$1 p=$2 i
	for i in $(seq 1 100); do (exec 3<>"/dev/tcp/$h/$p") 2>/dev/null && return 0; sleep 0.1; done
	return 1
}
wait_addr() {
	local ns=$1 dev=$2 cidr=$3 i
	for i in $(seq 1 100); do
		nsenter -t "$ns" -n ip -4 addr show dev "$dev" 2>/dev/null | grep -qF "inet $cidr" && return 0
		sleep 0.1
	done
	return 1
}

for cmd in go unshare nsenter ip curl python3 iptables; do
	command -v "$cmd" >/dev/null || { echo "missing $cmd" >&2; exit 1; }
done
[[ -e /dev/net/tun ]] || { echo "missing /dev/net/tun" >&2; exit 1; }

echo "== build =="
go build -o bin/relay ./cmd/relay
go build -o bin/client ./cmd/client
go build -o bin/tlsgate ./cmd/tlsgate
go build -o bin/linkaudit ./cmd/linkaudit

echo "== namespaces + veth =="
ip link set lo up
unshare -n sleep 600 & CLIENT_NS=$!
unshare -n sleep 600 & WAN_NS=$!
for ns in "$CLIENT_NS" "$WAN_NS"; do
	for i in $(seq 1 50); do [[ -e "/proc/$ns/ns/net" ]] && break; sleep 0.1; done
done

ip link add veth-c type veth peer name veth-h
ip link set veth-c netns "$CLIENT_NS"
ip addr add 10.200.1.1/24 dev veth-h
ip link set veth-h up
nsenter -t "$CLIENT_NS" -n ip link set lo up
nsenter -t "$CLIENT_NS" -n ip addr add 10.200.1.2/24 dev veth-c
nsenter -t "$CLIENT_NS" -n ip link set veth-c up

ip link add veth-wan type veth peer name veth-wan-in
ip link set veth-wan-in netns "$WAN_NS"
ip addr add 203.0.113.254/24 dev veth-wan
ip link set veth-wan up
nsenter -t "$WAN_NS" -n ip link set lo up
nsenter -t "$WAN_NS" -n ip addr add 203.0.113.1/24 dev veth-wan-in
nsenter -t "$WAN_NS" -n ip link set veth-wan-in up

echo "== forwarding + NAT =="
sysctl -qw net.ipv4.ip_forward=1
iptables -t nat -F
iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o veth-wan -j MASQUERADE
iptables -F FORWARD
iptables -A FORWARD -i dvpn1 -o veth-wan -j ACCEPT
iptables -A FORWARD -i veth-wan -o dvpn1 -j ACCEPT

cat > "$TMP/routes.json" <<'EOF'
{"entry-0":"127.0.0.1:17101","middle-0":"127.0.0.1:17102","exit-0":"127.0.0.1:17103"}
EOF

echo "== relays =="
bin/relay -id entry-0 -role entry -listen 0.0.0.0:17101 \
	-routes "$TMP/routes.json" -identity-out "$TMP/entry.id" \
	-control-addr 127.0.0.1:17201 > "$TMP/entry.log" 2>&1 & PIDS+=($!)
bin/relay -id middle-0 -role middle -listen 127.0.0.1:17102 \
	-routes "$TMP/routes.json" -identity-out "$TMP/middle.id" \
	-control-addr 127.0.0.1:17202 > "$TMP/middle.log" 2>&1 & PIDS+=($!)
bin/relay -id exit-0 -role exit -listen 127.0.0.1:17103 \
	-routes "$TMP/routes.json" -identity-out "$TMP/exit.id" \
	-control-addr 127.0.0.1:17203 \
	-tun -tun-name dvpn1 -tun-ip 10.99.0.1/24 -tun-mtu 800 \
	> "$TMP/exit.log" 2>&1 & PIDS+=($!)

for f in entry.id middle.id exit.id; do wait_file "$TMP/$f" || fail "missing $f"; done
for f in entry middle exit; do wait_log "$TMP/$f.log" "listening on" || fail "$f did not listen"; done
wait_log "$TMP/exit.log" "tun device dvpn1" || fail "exit TUN not ready"
ip -4 addr show dev dvpn1 | grep -qF 'inet 10.99.0.1/24' || fail "exit TUN address missing"

echo "== tlsgate =="
bin/tlsgate -listen 10.200.1.1:17443 -entry 127.0.0.1:17101 -frame 1024 \
	-tls-name dvpn.local -ech -ech-out "$TMP/ech.bin" > "$TMP/gate.log" 2>&1 & PIDS+=($!)
wait_file "$TMP/ech.bin" || fail "no ECH config"
wait_log "$TMP/gate.log" "tlsgate listening on" || fail "tlsgate not listening"

echo "== WAN HTTP server =="
nsenter -t "$WAN_NS" -n python3 -u -m http.server 8080 --bind 203.0.113.1 --directory "$ROOT" \
	> "$TMP/wan-http.log" 2>&1 & PIDS+=($!)
wait_log "$TMP/wan-http.log" "Serving HTTP on" || fail "WAN http server not listening"

echo "== client =="
nsenter -t "$CLIENT_NS" -n bin/client \
	-tun -tun-name dvpn0 -tun-ip 10.99.0.2/24 -tun-mtu 800 \
	-tls -tls-gate 10.200.1.1:17443 -tls-name dvpn.local -tls-insecure \
	-ech-config "$TMP/ech.bin" \
	-entry 127.0.0.1:17101 -path entry-0,middle-0,exit-0 \
	-id-entry "$TMP/entry.id" -id-middle "$TMP/middle.id" -id-exit "$TMP/exit.id" \
	> "$TMP/client.log" 2>&1 & CLIENT_PID=$!
PIDS+=("$CLIENT_PID")
wait_addr "$CLIENT_NS" dvpn0 10.99.0.2/24 || fail "client TUN not ready"

# Route the fake WAN through the tunnel.
nsenter -t "$CLIENT_NS" -n ip route add 203.0.113.0/24 dev dvpn0 || fail "client route failed"

echo "== curl through exit NAT =="
OUT=""
RC=1
for attempt in $(seq 1 10); do
	set +e
	OUT=$(nsenter -t "$CLIENT_NS" -n curl -sS --max-time 5 http://203.0.113.1:8080/ 2>&1)
	RC=$?
	set -e
	[[ $RC -eq 0 ]] && break
	sleep 0.5
done
[[ $RC -eq 0 ]] || fail "curl through NAT failed: $OUT"
grep -qF 'README.md' <<<"$OUT" || fail "unexpected HTTP body: $OUT"
echo "$OUT" | head -5

grep -qF '203.0.113.254' "$TMP/wan-http.log" ||
	fail "WAN log does not show the NAT source 203.0.113.254"
grep -qF '10.99.0.2' "$TMP/wan-http.log" &&
	fail "WAN log shows the inner client IP; NAT did not happen"

echo "== linkaudit =="
sleep 1
set +e
bin/linkaudit -relays "entry-0=http://127.0.0.1:17201,middle-0=http://127.0.0.1:17202,exit-0=http://127.0.0.1:17203" > "$TMP/linkaudit.log" 2>&1
RC=$?
set -e
cat "$TMP/linkaudit.log"
[[ $RC -eq 0 ]] || fail "linkaudit failed"

echo
echo "OK: exit NAT demo passed"
echo "  client TUN 10.99.0.2 -> onion -> exit TUN -> MASQUERADE 203.0.113.254 -> WAN 203.0.113.1"
echo "  $(tail -n 1 "$TMP/linkaudit.log")"
echo "  logs: $TMP"
