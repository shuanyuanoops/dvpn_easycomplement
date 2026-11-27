#!/usr/bin/env bash
# End-to-end demo combining the three real-transport pieces:
#
#   client netns (veth 10.200.0.2)
#     |- TLS 1.3 + ECH --> tlsgate 10.200.0.1:17443
#     |                       `- UDP --> entry-0 10.200.0.1:17101
#     |                                   -> middle-0 127.0.0.1:17102
#     |                                   -> exit-0   127.0.0.1:17103
#     |                                                  `- TUN dvpn1 10.99.0.1
#     `- TUN dvpn0 10.99.0.2 --HTTP--> 10.99.0.1:8080 (python http.server)
#
# After the HTTP fetch, linkaudit pulls the signed per-link halves and packet
# hash challenges from the relays' control endpoints (17201/17202/17203).
#
# Runs in a user namespace; no root required. Needs /dev/net/tun.
set -euo pipefail

if [[ "${DVPN_E2E:-}" != "1" ]]; then
	exec unshare -Urnm env DVPN_E2E=1 bash "$(cd "$(dirname "$0")" && pwd)/$(basename "$0")" "$@"
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TMP=/tmp/dvpn-e2e
rm -rf "$TMP"
mkdir -p "$TMP" bin

CLIENT_NS_PID=""
CLIENT_PID=""
PIDS=()

dump_logs() {
	local name
	for name in client gate entry middle exit http linkaudit; do
		[[ -s "$TMP/$name.log" ]] || continue
		echo "--- $name ---" >&2
		cat "$TMP/$name.log" >&2 || true
	done
}

fail() {
	echo "FAIL: $*" >&2
	dump_logs
	exit 1
}

cleanup() {
	local p i alive
	# The TUN client blocks in read(2) on /dev/net/tun and does not wake on
	# SIGTERM, so stop it hard and give the relays a moment to write receipts.
	for p in "${PIDS[@]:-}"; do
		if [[ "$p" != "$CLIENT_PID" ]]; then
			kill -TERM "$p" 2>/dev/null || true
		fi
	done
	if [[ -n "$CLIENT_PID" ]]; then
		kill -KILL "$CLIENT_PID" 2>/dev/null || true
	fi
	for i in $(seq 1 20); do
		alive=0
		for p in "${PIDS[@]:-}"; do
			if [[ "$p" != "$CLIENT_PID" ]] && kill -0 "$p" 2>/dev/null; then alive=1; fi
		done
		if [[ "$alive" -eq 0 ]]; then break; fi
		sleep 0.05
	done
	for p in "${PIDS[@]:-}"; do kill -KILL "$p" 2>/dev/null || true; done
	for p in "${PIDS[@]:-}"; do wait "$p" 2>/dev/null || true; done
	if [[ -n "$CLIENT_NS_PID" ]]; then
		kill -TERM "$CLIENT_NS_PID" 2>/dev/null || true
		wait "$CLIENT_NS_PID" 2>/dev/null || true
	fi
	ip link del veth-h 2>/dev/null || true
	return 0
}
trap cleanup EXIT

wait_file() {
	local f=$1 i
	for i in $(seq 1 100); do
		if [[ -s "$f" ]]; then return 0; fi
		sleep 0.1
	done
	return 1
}

wait_log() {
	local f=$1 pat=$2 i
	for i in $(seq 1 100); do
		if [[ -f "$f" ]] && grep -qF -- "$pat" "$f"; then return 0; fi
		sleep 0.1
	done
	return 1
}

wait_tcp() {
	local host=$1 port=$2 i
	for i in $(seq 1 100); do
		if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
			return 0
		fi
		sleep 0.1
	done
	return 1
}

wait_ns_addr() {
	local ns_pid=$1 dev=$2 cidr=$3 i
	for i in $(seq 1 100); do
		if nsenter -t "$ns_pid" -n ip -4 addr show dev "$dev" 2>/dev/null | grep -qF "inet $cidr"; then
			return 0
		fi
		sleep 0.1
	done
	return 1
}

for cmd in go unshare nsenter ip curl python3; do
	command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: missing required command: $cmd" >&2; exit 1; }
done
[[ -e /dev/net/tun ]] || { echo "ERROR: /dev/net/tun is missing" >&2; exit 1; }

echo "== build =="
go build -o bin/relay ./cmd/relay
go build -o bin/client ./cmd/client
go build -o bin/tlsgate ./cmd/tlsgate
go build -o bin/linkaudit ./cmd/linkaudit

echo "== client netns + veth =="
ip link set lo up
unshare -n sleep 600 &
CLIENT_NS_PID=$!
for i in $(seq 1 50); do [[ -e "/proc/$CLIENT_NS_PID/ns/net" ]] && break; sleep 0.1; done
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

echo "== relays (entry/middle/exit + control) =="
bin/relay -id entry-0 -role entry -name entry-0 -listen 10.200.0.1:17101 \
	-routes "$TMP/routes.json" -identity-out "$TMP/entry.id" \
	-receipt "$TMP/entry.json" -control-addr 127.0.0.1:17201 \
	> "$TMP/entry.log" 2>&1 &
PIDS+=($!)
bin/relay -id middle-0 -role middle -name middle-0 -listen 127.0.0.1:17102 \
	-routes "$TMP/routes.json" -identity-out "$TMP/middle.id" \
	-receipt "$TMP/middle.json" -control-addr 127.0.0.1:17202 \
	> "$TMP/middle.log" 2>&1 &
PIDS+=($!)
bin/relay -id exit-0 -role exit -name exit-0 -listen 127.0.0.1:17103 \
	-routes "$TMP/routes.json" -identity-out "$TMP/exit.id" \
	-receipt "$TMP/exit.json" -control-addr 127.0.0.1:17203 \
	-tun -tun-name dvpn1 -tun-ip 10.99.0.1/24 -tun-mtu 800 \
	> "$TMP/exit.log" 2>&1 &
PIDS+=($!)

wait_file "$TMP/entry.id" || fail "entry identity was not written"
wait_file "$TMP/middle.id" || fail "middle identity was not written"
wait_file "$TMP/exit.id" || fail "exit identity was not written"
wait_log "$TMP/entry.log" "listening on" || fail "entry relay did not start listening"
wait_log "$TMP/middle.log" "listening on" || fail "middle relay did not start listening"
wait_log "$TMP/exit.log" "listening on" || fail "exit relay did not start listening"
wait_log "$TMP/exit.log" "tun device dvpn1" || fail "exit TUN was not configured"
ip -4 addr show dev dvpn1 2>/dev/null | grep -qF 'inet 10.99.0.1/24' ||
	fail "exit TUN dvpn1 does not have 10.99.0.1/24"
for port in 17201 17202 17203; do
	wait_tcp 127.0.0.1 "$port" || fail "control endpoint 127.0.0.1:$port is not listening"
done

echo "== tlsgate (TLS 1.3 + ECH) =="
bin/tlsgate -listen 10.200.0.1:17443 -entry 10.200.0.1:17101 -frame 1024 \
	-tls-name dvpn.local -ech -ech-out "$TMP/ech.bin" > "$TMP/gate.log" 2>&1 &
PIDS+=($!)
wait_file "$TMP/ech.bin" || fail "tlsgate did not write the ECH config"
wait_log "$TMP/gate.log" "tlsgate listening on" || fail "tlsgate did not start listening"

echo "== http server on exit TUN =="
python3 -u -m http.server 8080 --bind 10.99.0.1 --directory "$ROOT" > "$TMP/http.log" 2>&1 &
PIDS+=($!)
wait_tcp 10.99.0.1 8080 || fail "http.server did not start on 10.99.0.1:8080"
wait_log "$TMP/http.log" "Serving HTTP on" || fail "http.server did not report its listen address"

echo "== client in client netns (TUN + TLS + ECH) =="
nsenter -t "$CLIENT_NS_PID" -n bin/client \
	-tun -tun-name dvpn0 -tun-ip 10.99.0.2/24 -tun-mtu 800 \
	-tls -tls-gate 10.200.0.1:17443 -tls-name dvpn.local -tls-insecure \
	-ech-config "$TMP/ech.bin" \
	-entry 10.200.0.1:17101 -path entry-0,middle-0,exit-0 \
	-id-entry "$TMP/entry.id" -id-middle "$TMP/middle.id" -id-exit "$TMP/exit.id" \
	> "$TMP/client.log" 2>&1 &
CLIENT_PID=$!
PIDS+=("$CLIENT_PID")

wait_ns_addr "$CLIENT_NS_PID" dvpn0 10.99.0.2/24 || fail "client TUN dvpn0 was not configured"
kill -0 "$CLIENT_PID" 2>/dev/null || fail "client exited during startup"

echo "== curl through the tunnel =="
OUT=""
RC=1
for attempt in $(seq 1 10); do
	if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
		fail "client exited before curl succeeded (attempt $attempt)"
	fi
	set +e
	OUT=$(nsenter -t "$CLIENT_NS_PID" -n curl -sS --max-time 5 http://10.99.0.1:8080/ 2>&1)
	RC=$?
	set -e
	if [[ $RC -eq 0 ]]; then break; fi
	sleep 0.5
done
[[ $RC -eq 0 ]] || fail "curl http://10.99.0.1:8080/ failed: $OUT"
grep -qF 'README.md' <<<"$OUT" || fail "curl response is not the repo directory listing"
echo "$OUT" | head -5

echo "== tlsgate log check =="
grep -qF 'tls version=0x304 ech=true' "$TMP/gate.log" ||
	fail "tlsgate log does not contain 'tls version=0x304 ech=true'"
grep -F 'tls version=0x304 ech=true' "$TMP/gate.log" | head -1

echo "== linkaudit (per-link dual signatures + challenges) =="
# Let the last TUN packets drain so both halves of every link agree on counts.
sleep 1
set +e
bin/linkaudit -relays "entry-0=http://127.0.0.1:17201,middle-0=http://127.0.0.1:17202,exit-0=http://127.0.0.1:17203" \
	> "$TMP/linkaudit.log" 2>&1
RC=$?
set -e
cat "$TMP/linkaudit.log"
[[ $RC -eq 0 ]] || fail "linkaudit exited with status $RC"

line=$(tail -n 1 "$TMP/linkaudit.log")
grep -qF 'links=2 ok=2 failed=0' <<<"$line" ||
	fail "expected 'links=2 ok=2 failed=0', got: $line"
ok_challenges=$(sed -E 's/.*ok_challenges=([0-9]+).*/\1/' <<<"$line")
if [[ ! "$ok_challenges" =~ ^[0-9]+$ ]] || [[ "$ok_challenges" -le 0 ]]; then
	fail "expected ok_challenges > 0, got: $line"
fi

echo
echo "OK: end-to-end demo passed"
echo "  HTTP: client TUN 10.99.0.2 -> TLS1.3+ECH -> entry -> middle -> exit TUN 10.99.0.1"
echo "  linkaudit: $line"
echo "  logs: $TMP"
