package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"dvpn-sim/internal/circuit"
	"dvpn-sim/internal/frame"
	"dvpn-sim/internal/handshake"
	"dvpn-sim/internal/identity"
	"dvpn-sim/internal/link"
	"dvpn-sim/internal/model"
	"dvpn-sim/internal/onion"
	"dvpn-sim/internal/receipt"
	"dvpn-sim/internal/tun"
	"dvpn-sim/internal/usage"
)

// hopFieldSize is the width of a node id in an onion next-hop field and in the
// next-hop prefix of a sealed handshake message.
const hopFieldSize = 16

type linkStat struct {
	tag       uint64
	from      string
	to        string
	sentPkts  int64
	sentBytes int64
	recvPkts  int64
	recvBytes int64
	hashes    map[int][32]byte
}

type tracker struct {
	mu   sync.Mutex
	m    map[uint64]*linkStat
	id   string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newTracker(id string, pub ed25519.PublicKey, priv ed25519.PrivateKey) *tracker {
	return &tracker{m: map[uint64]*linkStat{}, id: id, pub: pub, priv: priv}
}

func (t *tracker) stat(tag uint64) *linkStat {
	st := t.m[tag]
	if st == nil {
		st = &linkStat{tag: tag, hashes: map[int][32]byte{}}
		t.m[tag] = st
	}
	return st
}

func (t *tracker) sender(tag uint64, from, to string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.stat(tag)
	st.from, st.to = from, to
}

func (t *tracker) receiver(tag uint64, to string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.stat(tag)
	st.to = to
}

func (t *tracker) sent(tag uint64, seq uint64, n int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.stat(tag)
	st.sentPkts++
	st.sentBytes += int64(n)
	st.hashes[int(seq)] = link.PacketHash(fmt.Sprintf("%d", tag), int(seq), int64(n))
}

func (t *tracker) recv(tag uint64, seq uint64, n int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.stat(tag)
	st.recvPkts++
	st.recvBytes += int64(n)
	st.hashes[int(seq)] = link.PacketHash(fmt.Sprintf("%d", tag), int(seq), int64(n))
}

func (t *tracker) halves() []link.Half {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []link.Half
	pub := hex.EncodeToString(t.pub)
	for _, st := range t.m {
		tag := fmt.Sprintf("%d", st.tag)
		if st.sentPkts > 0 {
			h := link.Half{Tag: tag, From: st.from, To: st.to, Role: "sender", Packets: st.sentPkts, Bytes: st.sentBytes, Pub: pub}
			link.SignHalf(&h, t.priv)
			out = append(out, h)
		}
		if st.recvPkts > 0 {
			h := link.Half{Tag: tag, To: t.id, Role: "receiver", Packets: st.recvPkts, Bytes: st.recvBytes, Pub: pub}
			link.SignHalf(&h, t.priv)
			out = append(out, h)
		}
	}
	return out
}

func (t *tracker) hashProof(tag string, seq int) (link.HashProof, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, st := range t.m {
		if fmt.Sprintf("%d", st.tag) != tag {
			continue
		}
		h, ok := st.hashes[seq]
		if !ok {
			return link.HashProof{}, false
		}
		p := link.HashProof{Tag: tag, Seq: seq, Hash: hex.EncodeToString(h[:]), Pub: hex.EncodeToString(t.pub)}
		link.SignHash(&p, t.priv)
		return p, true
	}
	return link.HashProof{}, false
}

func (t *tracker) serve(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/links", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(t.halves())
	})
	mux.HandleFunc("/hash", func(w http.ResponseWriter, r *http.Request) {
		seq, err := strconv.Atoi(r.URL.Query().Get("seq"))
		if err != nil {
			http.Error(w, "bad seq", http.StatusBadRequest)
			return
		}
		p, ok := t.hashProof(r.URL.Query().Get("tag"), seq)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(p)
	})
	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Printf("control %s: %v", addr, err)
		}
	}()
}

type keyStore struct {
	mu sync.Mutex
	m  map[uint64][]byte
}

func newKeyStore() *keyStore { return &keyStore{m: map[uint64][]byte{}} }

func (k *keyStore) set(tag uint64, key []byte) {
	k.mu.Lock()
	k.m[tag] = append([]byte(nil), key...)
	k.mu.Unlock()
}

func (k *keyStore) get(tag uint64) []byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.m[tag]
}

func takeFirst(b []byte) ([]byte, []byte, error) {
	if len(b) < 2 {
		return nil, nil, fmt.Errorf("short handshake")
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	if len(b) < 2+n {
		return nil, nil, fmt.Errorf("short handshake body")
	}
	return b[2 : 2+n], b[2+n:], nil
}

func main() {
	id := flag.String("id", "", "this relay's node id")
	role := flag.String("role", "entry", "entry|middle|exit")
	name := flag.String("name", "", "receipt name (default: id)")
	runID := flag.String("run-id", "test", "run id for receipts")
	receiptPath := flag.String("receipt", "", "write a signed receipt JSON here on exit")
	pubkeyOut := flag.String("pubkey-out", "", "write the X25519 public key hex here")
	identityOut := flag.String("identity-out", "", "write the signed identity document here")
	keyHex := flag.String("key", "", "optional fixed 32-byte AES key, hex (legacy)")
	listen := flag.String("listen", "127.0.0.1:17001", "UDP listen address")
	nextID := flag.String("next-id", "", "expected next hop id (fallback when -routes is unset)")
	nextAddrFlag := flag.String("next-addr", "", "next hop UDP address (fallback when -routes is unset)")
	routesPath := flag.String("routes", "", "JSON file mapping next-hop node IDs to UDP addresses; when set it is authoritative")
	destAddr := flag.String("dest", "", "destination UDP address (exit only)")
	frameSize := flag.Int("frame", 1024, "fixed wire frame size")
	tagTTL := flag.Duration("tag-ttl", 5*time.Minute, "idle timeout for circuit tags")
	tunMode := flag.Bool("tun", false, "exit: write payloads to a TUN device and return its packets")
	tunName := flag.String("tun-name", "dvpn1", "exit TUN device name")
	tunMTU := flag.Int("tun-mtu", 800, "exit TUN MTU (must fit the onion payload)")
	tunIP := flag.String("tun-ip", "10.99.0.1/24", "exit TUN address (CIDR)")
	controlAddr := flag.String("control-addr", "", "HTTP control address for link receipts/challenges (e.g. 127.0.0.1:17201)")
	claimOut := flag.String("claim-out", "", "exit: write signed usage claims here on SIGTERM")
	claimEpoch := flag.Int64("claim-epoch", 1, "exit: usage epoch")
	flag.Parse()

	if *id == "" {
		log.Fatal("-id is required")
	}
	var fixedKey []byte
	if *keyHex != "" {
		k, err := hex.DecodeString(*keyHex)
		if err != nil || len(k) != 32 {
			log.Fatal("-key must be 32 bytes hex")
		}
		fixedKey = k
	}
	if *name == "" {
		*name = *id
	}

	staticPub, staticPriv, err := handshake.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	identityPub, identityPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	if *identityOut != "" {
		doc := identity.Sign(*id, staticPub, identityPub, identityPriv)
		if err := identity.Write(*identityOut, doc); err != nil {
			log.Fatalf("identity-out: %v", err)
		}
	}
	if *pubkeyOut != "" {
		if err := os.WriteFile(*pubkeyOut, []byte(hex.EncodeToString(staticPub)+"\n"), 0o600); err != nil {
			log.Fatalf("pubkey-out: %v", err)
		}
	}
	fmt.Printf("relay %s pubkey=%s\n", *id, hex.EncodeToString(staticPub))

	laddr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	var nextAddr *net.UDPAddr
	if *nextAddrFlag != "" {
		nextAddr, err = net.ResolveUDPAddr("udp", *nextAddrFlag)
		if err != nil {
			log.Fatal(err)
		}
	}
	var dest *net.UDPAddr
	if *destAddr != "" {
		dest, err = net.ResolveUDPAddr("udp", *destAddr)
		if err != nil {
			log.Fatal(err)
		}
	}
	var routes map[string]*net.UDPAddr
	if *routesPath != "" {
		routes, err = loadRoutes(*routesPath)
		if err != nil {
			log.Fatalf("routes: %v", err)
		}
		log.Printf("relay %s: loaded %d routes from %s", *id, len(routes), *routesPath)
	}
	rt := &router{routes: routes, nextID: *nextID, nextAddr: nextAddr}
	isExit := *role == "exit" || dest != nil

	receiptPriv := identityPriv
	start := time.Now()

	state := circuit.NewState()
	var seenMu sync.Mutex
	seen := map[uint64]uint64{}
	acceptSeq := func(tag, seq uint64) bool {
		seenMu.Lock()
		defer seenMu.Unlock()
		if last, ok := seen[tag]; ok && seq <= last {
			return false
		}
		seen[tag] = seq
		return true
	}
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if n := state.Cleanup(time.Now(), *tagTTL); n > 0 {
				log.Printf("expired %d circuits", n)
			}
		}
	}()
	keys := newKeyStore()
	replyKeys := newKeyStore()
	hsNonces := newKeyStore()
	tr := newTracker(*id, identityPub, identityPriv)
	if *controlAddr != "" {
		tr.serve(*controlAddr)
	}

	var tunDev *tun.Native
	type tunPeer struct {
		addr *net.UDPAddr
		key  []byte
		tag  uint64
		ip   net.IP
	}
	var tunMu sync.Mutex
	tunPeers := map[uint64]tunPeer{}
	clientIPs := map[uint64]net.IP{}
	type usageStat struct {
		bytes   int64
		packets int64
	}
	tunStats := map[string]usageStat{}
	if *tunMode && isExit {
		tunDev, err = tun.Open(*tunName)
		if err != nil {
			log.Fatalf("tun %s: %v", *tunName, err)
		}
		defer tunDev.Close()
		if err := tun.Configure(tunDev.Name(), *tunIP, *tunMTU); err != nil {
			log.Fatalf("tun configure: %v", err)
		}
		log.Printf("tun device %s ip=%s mtu=%d", tunDev.Name(), *tunIP, *tunMTU)
		go func() {
			buf := make([]byte, *tunMTU)
			for {
				n, err := tunDev.Read(buf)
				if err != nil {
					log.Printf("tun read: %v", err)
					return
				}
				dst := ipv4Dst(buf[:n])
				if dst == nil {
					continue
				}
				tunMu.Lock()
				var peer *tunPeer
				for _, p := range tunPeers {
					if p.ip != nil && p.ip.Equal(dst) {
						cp := p
						peer = &cp
						break
					}
				}
				tunMu.Unlock()
				if peer == nil {
					continue
				}
				enc, err := handshake.SealPayload(peer.key, buf[:n])
				if err != nil {
					continue
				}
				out, err := frame.Encode(enc, *frameSize, frame.TypeReply, peer.tag, 0)
				if err != nil {
					continue
				}
				conn.WriteToUDP(out, peer.addr)
			}
		}()
	}
	var packets, bytesIn, bytesOut atomic.Uint64
	var replyPackets, replyIn, replyOut atomic.Uint64
	var hsPackets atomic.Uint64

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		if *claimOut != "" {
			tunMu.Lock()
			var claims []usage.Claim
			for sess, us := range tunStats {
				c := usage.Claim{
					Session: sess, Node: *id, Epoch: *claimEpoch,
					Bytes: us.bytes, Packets: us.packets, Pub: identityPub,
				}
				usage.SignClaim(&c, identityPriv)
				claims = append(claims, c)
			}
			tunMu.Unlock()
			if b, err := json.Marshal(claims); err == nil {
				if err := os.WriteFile(*claimOut, b, 0o600); err != nil {
					log.Printf("claim write: %v", err)
				}
			}
		}
		if *receiptPath != "" {
			r := receipt.New(*name, *role, *runID, start, time.Now(),
				int64(packets.Load()), int64(bytesIn.Load()), int64(bytesOut.Load()), receiptPriv)
			if err := receipt.Write(*receiptPath, r); err != nil {
				log.Printf("receipt: %v", err)
			}
		}
		fmt.Printf("relay %s packets=%d in=%d out=%d replies=%d reply_in=%d reply_out=%d handshakes=%d\n",
			*id, packets.Load(), bytesIn.Load(), bytesOut.Load(),
			replyPackets.Load(), replyIn.Load(), replyOut.Load(), hsPackets.Load())
		conn.Close()
		os.Exit(0)
	}()

	fmt.Printf("relay %s listening on %s\n", *id, *listen)
	buf := make([]byte, 4096)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		inner, typ, tag, seq, err := frame.Decode(buf[:n])
		if err != nil {
			log.Printf("bad frame: %v", err)
			continue
		}
		if typ == frame.TypeForward {
			tr.recv(tag, seq, len(inner))
		}

		if typ == frame.TypeHandshake {
			hsPackets.Add(1)
			sealed, rest, err := takeFirst(inner)
			if err != nil {
				log.Printf("handshake: %v", err)
				continue
			}
			key, err := handshake.Open(staticPriv, sealed)
			if err != nil {
				log.Printf("handshake open: %v", err)
				continue
			}
			st := state.Forward(tag, remote, isExit)
			if isExit {
				if len(key) != 76 {
					log.Printf("exit handshake key len=%d", len(key))
					continue
				}
				keys.set(tag, key[:32])
				replyKeys.set(tag, key[32:64])
				hsNonces.set(tag, key[64:72])
				tunMu.Lock()
				clientIPs[tag] = net.IPv4(key[72], key[73], key[74], key[75])
				tunMu.Unlock()
				ack, err := handshake.SealPayload(key[32:64], key[64:72])
				if err != nil {
					log.Printf("ack seal: %v", err)
					continue
				}
				out, err := frame.Encode(ack, *frameSize, frame.TypeAck, tag, 0)
				if err != nil {
					log.Printf("ack encode: %v", err)
					continue
				}
				if _, err := conn.WriteToUDP(out, st.Prev); err != nil {
					log.Printf("ack send: %v", err)
				}
				continue
			}
			hop, sessionKey, err := splitHopKey(key, model.NodeID(*nextID))
			if err != nil {
				log.Printf("handshake: %v", err)
				continue
			}
			keys.set(tag, sessionKey)
			tr.sender(st.OutTag, *id, string(hop))
			nextHopAddr, ok := rt.resolve(hop)
			if !ok {
				continue
			}
			out, err := frame.Encode(rest, *frameSize, frame.TypeHandshake, st.OutTag, 0)
			if err != nil {
				log.Printf("handshake encode: %v", err)
				continue
			}
			if _, err := conn.WriteToUDP(out, nextHopAddr); err != nil {
				log.Printf("handshake forward: %v", err)
			}
			continue
		}

		if typ == frame.TypeReply || typ == frame.TypeAck {
			replyPackets.Add(1)
			replyIn.Add(uint64(n))
			peer, outTag, ok := state.ReplyPeer(tag, isExit)
			if !ok {
				log.Printf("reply for unknown tag %d", tag)
				continue
			}
			out, err := frame.Encode(inner, *frameSize, typ, outTag, 0)
			if err != nil {
				log.Printf("encode reply: %v", err)
				continue
			}
			if _, err := conn.WriteToUDP(out, peer); err != nil {
				log.Printf("forward reply: %v", err)
			} else {
				replyOut.Add(uint64(len(out)))
			}
			continue
		}

		if !acceptSeq(tag, seq) {
			log.Printf("replay/old seq tag=%d seq=%d", tag, seq)
			continue
		}
		packets.Add(1)
		bytesIn.Add(uint64(n))
		st := state.Forward(tag, remote, isExit)

		key := fixedKey
		if key == nil {
			key = keys.get(tag)
		}
		if key == nil {
			log.Printf("no key for tag %d", tag)
			continue
		}

		nextHop, inner2, err := onion.Peel(inner, key)
		if err != nil {
			log.Printf("peel: %v", err)
			continue
		}

		if nextHop == "dest" {
			if tunDev != nil {
				pkt := inner2
				if n := ipLen(pkt); n > 0 {
					pkt = pkt[:n]
				}
				if _, err := tunDev.Write(pkt); err != nil {
					log.Printf("tun write: %v", err)
					continue
				}
				if cip := clientIPs[tag]; cip != nil {
					tunMu.Lock()
					us := tunStats[cip.String()]
					us.bytes += int64(len(pkt))
					us.packets++
					tunStats[cip.String()] = us
					tunMu.Unlock()
				}
				rk := replyKeys.get(tag)
				if rk == nil {
					log.Printf("no reply key for tag %d", tag)
					continue
				}
				tunMu.Lock()
				tunPeers[tag] = tunPeer{addr: st.Prev, key: rk, tag: tag, ip: clientIPs[tag]}
				tunMu.Unlock()
				continue
			}
			if dest == nil {
				log.Printf("no -dest configured, dropping payload")
				continue
			}
			if _, err := conn.WriteToUDP(inner2, dest); err != nil {
				log.Printf("write dest: %v", err)
			} else {
				bytesOut.Add(uint64(len(inner2)))
			}
			replyKey := replyKeys.get(tag)
			if replyKey == nil {
				log.Printf("no reply key for tag %d", tag)
				continue
			}
			enc, err := handshake.SealPayload(replyKey, inner2)
			if err != nil {
				log.Printf("reply seal: %v", err)
				continue
			}
			out, err := frame.Encode(enc, *frameSize, frame.TypeReply, tag, 0)
			if err == nil {
				if _, err := conn.WriteToUDP(out, st.Prev); err != nil {
					log.Printf("write reply: %v", err)
				} else {
					replyOut.Add(uint64(len(out)))
				}
			}
			continue
		}

		next, ok := rt.resolve(nextHop)
		if !ok {
			continue
		}
		tr.sent(st.OutTag, seq, len(inner2))
		out, err := frame.Encode(inner2, *frameSize, frame.TypeForward, st.OutTag, seq)
		if err != nil {
			log.Printf("encode: %v", err)
			continue
		}
		if _, err := conn.WriteToUDP(out, next); err != nil {
			log.Printf("forward: %v", err)
			continue
		}
		bytesOut.Add(uint64(len(out)))
	}
}

// router resolves a next-hop node ID to a UDP address. A loaded routes file is
// authoritative: unknown IDs are dropped. Without one, the legacy
// -next-id/-next-addr pair is used.
type router struct {
	routes   map[string]*net.UDPAddr
	nextID   string
	nextAddr *net.UDPAddr
}

func (r *router) resolve(hop model.NodeID) (*net.UDPAddr, bool) {
	if r.routes != nil {
		addr, ok := r.routes[string(hop)]
		if !ok {
			log.Printf("no route for next hop %q, dropping", hop)
			return nil, false
		}
		return addr, true
	}
	if r.nextID != "" && string(hop) != r.nextID {
		log.Printf("next hop mismatch: got %s want %s", hop, r.nextID)
		return nil, false
	}
	if r.nextAddr == nil {
		log.Printf("no route or -next-addr for next hop %q, dropping", hop)
		return nil, false
	}
	return r.nextAddr, true
}

// loadRoutes reads a JSON object mapping node ID to UDP address.
func loadRoutes(path string) (map[string]*net.UDPAddr, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]string
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	out := make(map[string]*net.UDPAddr, len(raw))
	for node, addr := range raw {
		if strings.TrimSpace(node) == "" || strings.TrimSpace(addr) == "" {
			return nil, fmt.Errorf("%s: empty id or address", path)
		}
		a, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, fmt.Errorf("%s: route %s: %w", path, node, err)
		}
		out[node] = a
	}
	return out, nil
}

func ipLen(pkt []byte) int {
	if len(pkt) < 20 {
		return 0
	}
	switch pkt[0] >> 4 {
	case 4:
		n := int(binary.BigEndian.Uint16(pkt[2:4]))
		if n >= 20 && n <= len(pkt) {
			return n
		}
	case 6:
		if len(pkt) < 40 {
			return 0
		}
		n := 40 + int(binary.BigEndian.Uint16(pkt[4:6]))
		if n <= len(pkt) {
			return n
		}
	}
	return 0
}

func ipv4Dst(pkt []byte) net.IP {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil
	}
	return net.IP(pkt[16:20])
}

// splitHopKey decodes the sealed handshake message of a non-exit relay.
// Current clients seal nextHopID(16) || sessionKey(32); older clients sealed
// only sessionKey(32), in which case the configured -next-id is the hop.
func splitHopKey(msg []byte, fallback model.NodeID) (model.NodeID, []byte, error) {
	switch len(msg) {
	case 32:
		return fallback, msg, nil
	case hopFieldSize + 32:
		raw := msg[:hopFieldSize]
		n := 0
		for n < len(raw) && raw[n] != 0 {
			n++
		}
		hop := model.NodeID(raw[:n])
		if hop == "" {
			return "", nil, fmt.Errorf("empty next hop in handshake")
		}
		return hop, msg[hopFieldSize:], nil
	default:
		return "", nil, fmt.Errorf("unexpected handshake key length %d", len(msg))
	}
}
