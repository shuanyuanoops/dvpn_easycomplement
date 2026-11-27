#!/usr/bin/env bash
# Two clients, two netns, two TUN addresses, one entry/middle/exit.
# Verifies that the exit demuxes return packets by destination inner IP.
set -euo pipefail

if [[ "${DVPN_MULTI:-}" != "1" ]]; then
	exec unshare -Urnm env DVPN_MULTI=1 bash "$(cd "$(dirname "$0")" && pwd)/$(basename "$0")" "$@"
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TMP=/tmp/dvpn-multi
rm -rf "$TMP"
mkdir -p "$TMP" bin

NS1=""
NS2=""
C1=""
C2=""
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
		if [[ "$p" != "$C1" && "$p" != "$C2" ]]; then kill -TERM "$p" 2>/dev/null || true; fi
	done
	for p in "$C1" "$C2"; do
		[[ -n "$p" ]] && kill -KILL "$p" 2>/dev/null || true
	done
	for i in $(seq 1 30); do
		alive=0
		for p in "${PIDS[@]:-}"; do
			[[ "$p" == "$C1" || "$p" == "$C2" ]] && continue
			kill -0 "$p" 2>/dev/null && alive=1
		done
		[[ "$alive" -eq 0 ]] && break
		sleep 0.05
	done
	for p in "${PIDS[@]:-}"; do kill -KILL "$p" 2>/dev/null || true; done
	for p in "${PIDS[@]:-}"; do wait "$p" 2>/dev/null || true; done
	for p in "$NS1" "$NS2"; do
		[[ -n "$p" ]] && kill -TERM "$p" 2>/dev/null || true
		[[ -n "$p" ]] && wait "$p" 2>/dev/null || true
	done
	ip link del veth1-h 2>/dev/null || true
	ip link del veth2-h 2>/dev/null || true
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

for cmd in go unshare nsenter ip curl python3; do
	command -v "$cmd" >/dev/null || { echo "missing $cmd" >&2; exit 1; }
done
[[ -e /dev/net/tun ]] || { echo "missing /dev/net/tun" >&2; exit 1; }

echo "== build =="
go build -o bin/relay ./cmd/relay
go build -o bin/client ./cmd/client
go build -o bin/tlsgate ./cmd/tlsgate
go build -o bin/linkaudit ./cmd/linkaudit

echo "== two client netns =="
ip link set lo up
unshare -n sleep 600 & NS1=$!
unshare -n sleep 600 & NS2=$!
for ns in "$NS1" "$NS2"; do
	for i in $(seq 1 50); do [[ -e "/proc/$ns/ns/net" ]] && break; sleep 0.1; done
done

ip link add veth1-c type veth peer name veth1-h
ip link set veth1-c netns "$NS1"
ip addr add 10.200.1.1/24 dev veth1-h
ip link set veth1-h up
nsenter -t "$NS1" -n ip link set lo up
nsenter -t "$NS1" -n ip addr add 10.200.1.2/24 dev veth1-c
nsenter -t "$NS1" -n ip link set veth1-c up

ip link add veth2-c type veth peer name veth2-h
ip link set veth2-c netns "$NS2"
ip addr add 10.200.2.1/24 dev veth2-h
ip link set veth2-h up
nsenter -t "$NS2" -n ip link set lo up
nsenter -t "$NS2" -n ip addr add 10.200.2.2/24 dev veth2-c
nsenter -t "$NS2" -n ip link set veth2-c up

cat > "$TMP/routes.json" <<'EOF'
{"entry-0":"127.0.0.1:17101","middle-0":"127.0.0.1:17102","exit-0":"127.0.0.1:17103"}
EOF

echo "== relays =="
bin/relay -id entry-0 -role entry -listen 0.0.0.0:17101 \
	-routes "$TMP/routes.json" -identity-out "$TMP/entry.id" \
	-receipt "$TMP/entry.json" -control-addr 127.0.0.1:17201 \
	> "$TMP/entry.log" 2>&1 & PIDS+=($!)
bin/relay -id middle-0 -role middle -listen 127.0.0.1:17102 \
	-routes "$TMP/routes.json" -identity-out "$TMP/middle.id" \
	-receipt "$TMP/middle.json" -control-addr 127.0.0.1:17202 \
	> "$TMP/middle.log" 2>&1 & PIDS+=($!)
bin/relay -id exit-0 -role exit -listen 127.0.0.1:17103 \
	-routes "$TMP/routes.json" -identity-out "$TMP/exit.id" \
	-receipt "$TMP/exit.json" -control-addr 127.0.0.1:17203 \
	-tun -tun-name dvpn1 -tun-ip 10.99.0.1/24 -tun-mtu 800 \
	> "$TMP/exit.log" 2>&1 & PIDS+=($!)

for f in entry.id middle.id exit.id; do wait_file "$TMP/$f" || fail "missing $f"; done
for f in entry middle exit; do wait_log "$TMP/$f.log" "listening on" || fail "$f did not listen"; done
wait_log "$TMP/exit.log" "tun device dvpn1" || fail "exit TUN not ready"
ip -4 addr show dev dvpn1 | grep -qF 'inet 10.99.0.1/24' || fail "exit TUN address missing"
for p in 17201 17202 17203; do wait_tcp 127.0.0.1 "$p" || fail "control $p not listening"; done

echo "== tlsgate =="
bin/tlsgate -listen 0.0.0.0:17443 -entry 127.0.0.1:17101 -frame 1024 \
	-tls-name dvpn.local -ech -ech-out "$TMP/ech.bin" > "$TMP/gate.log" 2>&1 & PIDS+=($!)
wait_file "$TMP/ech.bin" || fail "no ECH config"
wait_log "$TMP/gate.log" "tlsgate listening on" || fail "tlsgate not listening"

echo "== http server =="
python3 -u -m http.server 8080 --bind 10.99.0.1 --directory "$ROOT" > "$TMP/http.log" 2>&1 & PIDS+=($!)
wait_tcp 10.99.0.1 8080 || fail "http server not listening"

start_client() {
	local ns=$1 tunip=$2 gate=$3 log=$4
	nsenter -t "$ns" -n bin/client \
		-tun -tun-name dvpn0 -tun-ip "$tunip" -tun-mtu 800 \
		-tls -tls-gate "$gate" -tls-name dvpn.local -tls-insecure \
		-ech-config "$TMP/ech.bin" \
		-entry 127.0.0.1:17101 -path entry-0,middle-0,exit-0 \
		-id-entry "$TMP/entry.id" -id-middle "$TMP/middle.id" -id-exit "$TMP/exit.id" \
		> "$log" 2>&1 &
	echo $!
}

echo "== clients =="
C1=$(start_client "$NS1" 10.99.0.2/24 10.200.1.1:17443 "$TMP/client1.log")
PIDS+=("$C1")
C2=$(start_client "$NS2" 10.99.0.3/24 10.200.2.1:17443 "$TMP/client2.log")
PIDS+=("$C2")

wait_addr "$NS1" dvpn0 10.99.0.2/24 || fail "client1 TUN not ready"
wait_addr "$NS2" dvpn0 10.99.0.3/24 || fail "client2 TUN not ready"
kill -0 "$C1" 2>/dev/null || fail "client1 exited"
kill -0 "$C2" 2>/dev/null || fail "client2 exited"

echo "== curl from both clients =="
for ns in "$NS1" "$NS2"; do
	OUT=""
	RC=1
	for attempt in $(seq 1 10); do
		set +e
		OUT=$(nsenter -t "$ns" -n curl -sS --max-time 5 http://10.99.0.1:8080/ 2>&1)
		RC=$?
		set -e
		[[ $RC -eq 0 ]] && break
		sleep 0.5
	done
	[[ $RC -eq 0 ]] || fail "curl from ns $ns failed: $OUT"
	grep -qF 'README.md' <<<"$OUT" || fail "unexpected HTTP body from ns $ns"
done

sleep 1
grep -q '10.99.0.2' "$TMP/http.log" || fail "http log has no request from 10.99.0.2"
grep -q '10.99.0.3' "$TMP/http.log" || fail "http log has no request from 10.99.0.3"

echo "== linkaudit =="
set +e
bin/linkaudit -relays "entry-0=http://127.0.0.1:17201,middle-0=http://127.0.0.1:17202,exit-0=http://127.0.0.1:17203" > "$TMP/linkaudit.log" 2>&1
RC=$?
set -e
cat "$TMP/linkaudit.log"
[[ $RC -eq 0 ]] || fail "linkaudit failed"
line=$(tail -n 1 "$TMP/linkaudit.log")
grep -qF 'links=4 ok=4 failed=0' <<<"$line" || fail "expected 4 links, got: $line"
okc=$(sed -E 's/.*ok_challenges=([0-9]+).*/\1/' <<<"$line")
[[ "$okc" =~ ^[0-9]+$ ]] && [[ "$okc" -gt 0 ]] || fail "no successful challenges"

echo
echo "OK: two-client demo passed"
echo "  client1 TUN 10.99.0.2, client2 TUN 10.99.0.3"
echo "  $line"
echo "  logs: $TMP"
