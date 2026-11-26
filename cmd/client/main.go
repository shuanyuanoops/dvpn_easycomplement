package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"dvpn-sim/internal/frame"
	"dvpn-sim/internal/handshake"
	"dvpn-sim/internal/identity"
	"dvpn-sim/internal/model"
	"dvpn-sim/internal/onion"
	"dvpn-sim/internal/receipt"
	"dvpn-sim/internal/registry"
	"dvpn-sim/internal/transport"
	"dvpn-sim/internal/tun"
)

// hopFieldSize is the width of a node id in an onion next-hop field.
const hopFieldSize = 16

// assignment mirrors the controller's GET /assign response.
type assignment struct {
	Entry  registry.Relay `json:"entry"`
	Middle registry.Relay `json:"middle"`
	Exit   registry.Relay `json:"exit"`
}

// fetchAssignment asks the controller for a random entry/middle/exit triple.
func fetchAssignment(base string) (assignment, error) {
	url := strings.TrimRight(base, "/") + "/assign"
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return assignment{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return assignment{}, fmt.Errorf("GET %s: %s: %s", url, resp.Status, strings.TrimSpace(string(body)))
	}
	var a assignment
	if err := json.NewDecoder(resp.Body).Decode(&a); err != nil {
		return assignment{}, fmt.Errorf("decode %s: %w", url, err)
	}
	return a, nil
}

func main() {
	entry := flag.String("entry", "127.0.0.1:17001", "entry relay UDP address (fallback when -controller is unset)")
	controller := flag.String("controller", "", "controller base URL; GET /assign replaces -entry/-path/-id-*")
	pathStr := flag.String("path", "entry-0,middle-0,exit-0", "comma-separated hop ids (fallback when -controller is unset)")
	pubEntry := flag.String("pub-entry", "", "entry X25519 public key hex")
	pubMiddle := flag.String("pub-middle", "", "middle X25519 public key hex")
	pubExit := flag.String("pub-exit", "", "exit X25519 public key hex")
	idEntry := flag.String("id-entry", "", "entry identity document path")
	idMiddle := flag.String("id-middle", "", "middle identity document path")
	idExit := flag.String("id-exit", "", "exit identity document path")
	kEntry := flag.String("k-entry", "", "entry fixed AES key hex (legacy)")
	kMiddle := flag.String("k-middle", "", "middle fixed AES key hex (legacy)")
	kExit := flag.String("k-exit", "", "exit fixed AES key hex (legacy)")
	n := flag.Int("n", 4000, "number of cells to send")
	rate := flag.Int("rate", 4000, "cells per second")
	cellSize := flag.Int("cell", 1004, "onion cell size")
	frameSize := flag.Int("frame", 1024, "fixed wire frame size")
	name := flag.String("name", "client", "receipt name")
	runID := flag.String("run-id", "test", "run id for receipts")
	receiptPath := flag.String("receipt", "", "write a signed receipt JSON here")
	tunMode := flag.Bool("tun", false, "TUN data plane: read/write raw IP packets instead of synthetic payloads")
	tunName := flag.String("tun-name", "dvpn0", "TUN device name")
	tunMTU := flag.Int("tun-mtu", 800, "TUN MTU (must fit the onion payload)")
	tunIP := flag.String("tun-ip", "10.99.0.2/24", "TUN address (CIDR)")
	tlsMode := flag.Bool("tls", false, "connect to the entry through a TLS 1.3 gateway")
	tlsGate := flag.String("tls-gate", "127.0.0.1:17443", "TLS gateway address")
	tlsName := flag.String("tls-name", "dvpn.local", "TLS server name")
	tlsInsecure := flag.Bool("tls-insecure", true, "skip TLS certificate verification (demo)")
	echConfigPath := flag.String("ech-config", "", "ECHConfigList file for TLS ECH")
	flag.Parse()

	ids := strings.Split(*pathStr, ",")
	entryAddr := *entry
	idPaths := []string{*idEntry, *idMiddle, *idExit}
	if *controller != "" {
		// The controller assignment replaces -entry/-path/-id-*; the old flags
		// remain as the non-controller fallback.
		a, err := fetchAssignment(*controller)
		if err != nil {
			log.Fatalf("controller: %v", err)
		}
		if a.Entry.Role != string(model.RoleEntry) || a.Middle.Role != string(model.RoleMiddle) || a.Exit.Role != string(model.RoleExit) {
			log.Fatalf("controller: bad roles entry=%q middle=%q exit=%q", a.Entry.Role, a.Middle.Role, a.Exit.Role)
		}
		ids = []string{a.Entry.ID, a.Middle.ID, a.Exit.ID}
		idPaths = []string{a.Entry.Identity, a.Middle.Identity, a.Exit.Identity}
		entryAddr = a.Entry.Addr
		if entryAddr == "" {
			log.Fatal("controller: empty entry address")
		}
		for i, p := range idPaths {
			if p == "" {
				log.Fatalf("controller: empty identity path %d", i)
			}
		}
		fmt.Printf("controller assigned entry=%s (%s) middle=%s exit=%s\n", a.Entry.ID, a.Entry.Addr, a.Middle.ID, a.Exit.ID)
	}
	if len(ids) != 3 {
		log.Fatal("-path needs exactly 3 ids")
	}
	for i, id := range ids {
		if id == "" {
			log.Fatalf("hop %d: empty id", i)
		}
	}
	if ids[0] == ids[1] || ids[0] == ids[2] || ids[1] == ids[2] {
		log.Fatalf("duplicate hop ids: %s", strings.Join(ids, ","))
	}
	path := []model.NodeID{model.NodeID(ids[0]), model.NodeID(ids[1]), model.NodeID(ids[2])}

	pubHex := []string{*pubEntry, *pubMiddle, *pubExit}
	if idPaths[0] != "" || idPaths[1] != "" || idPaths[2] != "" {
		for i, p := range idPaths {
			if p == "" {
				log.Fatalf("missing identity path %d", i)
			}
			doc, err := identity.Read(p)
			if err != nil {
				log.Fatalf("identity %d: %v", i, err)
			}
			x, _, err := doc.Verify()
			if err != nil {
				log.Fatalf("identity %d: %v", i, err)
			}
			pubHex[i] = hex.EncodeToString(x)
		}
	}
	handshakeMode := pubHex[0] != "" || pubHex[1] != "" || pubHex[2] != ""
	keys := map[model.NodeID][]byte{}
	var handshakePayload []byte
	replyKey := make([]byte, 32)
	hsNonce := make([]byte, 8)
	ackCh := make(chan struct{}, 1)
	if handshakeMode {
		if _, err := rand.Read(replyKey); err != nil {
			log.Fatal(err)
		}
		if _, err := rand.Read(hsNonce); err != nil {
			log.Fatal(err)
		}
	}
	if handshakeMode {
		for i, h := range pubHex {
			if h == "" {
				log.Fatalf("missing -pub key %d", i)
			}
		}
		for i, h := range pubHex {
			pub, err := hex.DecodeString(h)
			if err != nil || len(pub) != 32 {
				log.Fatalf("pub key %d must be 32 bytes hex", i)
			}
			sessionKey := make([]byte, 32)
			if _, err := rand.Read(sessionKey); err != nil {
				log.Fatal(err)
			}
			var msg []byte
			if i == len(pubHex)-1 {
				msg = make([]byte, 0, 3*len(sessionKey))
				msg = append(msg, sessionKey...)
				msg = append(msg, replyKey...)
				msg = append(msg, hsNonce...)
			} else {
				// Bind the next hop into the sealed handshake so each relay can
				// look the address up in routes.json instead of a static
				// -next-addr. Layout: nextHopID(16) || sessionKey(32).
				if len(path[i+1]) > hopFieldSize {
					log.Fatalf("hop id %q longer than %d bytes", path[i+1], hopFieldSize)
				}
				msg = make([]byte, 0, hopFieldSize+len(sessionKey))
				hop := make([]byte, hopFieldSize)
				copy(hop, path[i+1])
				msg = append(msg, hop...)
				msg = append(msg, sessionKey...)
			}
			sealed, err := handshake.Seal(pub, msg)
			if err != nil {
				log.Fatal(err)
			}
			keys[path[i]] = sessionKey

			var l [2]byte
			binary.BigEndian.PutUint16(l[:], uint16(len(sealed)))
			handshakePayload = append(handshakePayload, l[:]...)
			handshakePayload = append(handshakePayload, sealed...)
		}
	} else {
		keyHex := []string{*kEntry, *kMiddle, *kExit}
		for i, id := range ids {
			k, err := hex.DecodeString(keyHex[i])
			if err != nil || len(k) != 32 {
				log.Fatalf("key %d must be 32 bytes hex", i)
			}
			keys[model.NodeID(id)] = k
		}
	}

	var err error
	var conn transport.FrameConn
	if *tlsMode {
		var echConfig []byte
		if *echConfigPath != "" {
			echConfig, err = os.ReadFile(*echConfigPath)
			if err != nil {
				log.Fatalf("ech config: %v", err)
			}
		}
		conn, err = transport.DialTLSECH(*tlsGate, *tlsName, *tlsInsecure, *frameSize, echConfig)
	} else {
		conn, err = transport.DialUDP(entryAddr, *frameSize)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	var cidBuf [8]byte
	if _, err := rand.Read(cidBuf[:]); err != nil {
		log.Fatal(err)
	}
	tag := binary.BigEndian.Uint64(cidBuf[:])

	var tunDev *tun.Native
	if *tunMode {
		tunDev, err = tun.Open(*tunName)
		if err != nil {
			log.Fatalf("tun %s: %v", *tunName, err)
		}
		defer tunDev.Close()
		if err := tun.Configure(tunDev.Name(), *tunIP, *tunMTU); err != nil {
			log.Fatalf("tun configure: %v", err)
		}
		log.Printf("tun device %s ip=%s mtu=%d", tunDev.Name(), *tunIP, *tunMTU)
	}

	var mu sync.Mutex
	var rtts []time.Duration
	go func() {
		for {
			frameBytes, err := conn.ReadFrame()
			if err != nil {
				return
			}
			inner, typ, gotTag, _, err := frame.Decode(frameBytes)
			if err != nil || gotTag != tag {
				continue
			}
			switch typ {
			case frame.TypeAck:
				plain, err := handshake.OpenPayload(replyKey, inner)
				if err == nil && bytes.Equal(plain, hsNonce) {
					select {
					case ackCh <- struct{}{}:
					default:
					}
				}
			case frame.TypeReply:
				plain, err := handshake.OpenPayload(replyKey, inner)
				if err != nil {
					continue
				}
				if *tunMode {
					if _, err := tunDev.Write(plain); err != nil {
						log.Printf("tun write: %v", err)
					}
					continue
				}
				if len(plain) < 16 {
					continue
				}
				ts := int64(binary.BigEndian.Uint64(plain[:8]))
				if ts <= 0 {
					continue
				}
				rtt := time.Since(time.Unix(0, ts))
				if rtt < 0 {
					rtt = 0
				}
				mu.Lock()
				rtts = append(rtts, rtt)
				mu.Unlock()
			}
		}
	}()

	if handshakeMode {
		acked := false
		for attempt := 0; attempt < 3 && !acked; attempt++ {
			out, err := frame.Encode(handshakePayload, *frameSize, frame.TypeHandshake, tag, 0)
			if err != nil {
				log.Fatal(err)
			}
			if err := conn.WriteFrame(out); err != nil {
				log.Fatal(err)
			}
			select {
			case <-ackCh:
				acked = true
			case <-time.After(300 * time.Millisecond):
			}
		}
		if !acked {
			log.Fatal("handshake ack timeout")
		}
	}

	var seq uint64
	payloadSize := onion.Capacity(*cellSize, len(ids))
	if payloadSize < 16 {
		log.Fatalf("cell too small: payload=%d", payloadSize)
	}
	payload := make([]byte, payloadSize)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	perTick := *rate / 1000
	if perTick < 1 {
		perTick = 1
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()

	start := time.Now()
	sent := 0
	var wireBytes int64
	if *tunMode {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sig
			tunDev.Close()
		}()
		buf := make([]byte, *tunMTU)
		for {
			n, err := tunDev.Read(buf)
			if err != nil {
				log.Printf("tun read: %v", err)
				break
			}
			if n == 0 {
				continue
			}
			if n > payloadSize {
				log.Printf("tun packet %d > payload %d, dropping", n, payloadSize)
				continue
			}
			cell, err := onion.Build(path, buf[:n], keys, *cellSize)
			if err != nil {
				log.Printf("onion build: %v", err)
				continue
			}
			seq++
			out, err := frame.Encode(cell, *frameSize, frame.TypeForward, tag, seq)
			if err != nil {
				log.Printf("frame encode: %v", err)
				continue
			}
			if err := conn.WriteFrame(out); err != nil {
				log.Printf("write: %v", err)
				break
			}
			wireBytes += int64(len(out))
			sent++
		}
	} else {
		for sent < *n {
			for j := 0; j < perTick && sent < *n; j++ {
				binary.BigEndian.PutUint64(payload[:8], uint64(time.Now().UnixNano()))
				binary.BigEndian.PutUint64(payload[8:16], uint64(sent))

				cell, err := onion.Build(path, payload, keys, *cellSize)
				if err != nil {
					log.Fatal(err)
				}
				seq++
				out, err := frame.Encode(cell, *frameSize, frame.TypeForward, tag, seq)
				if err != nil {
					log.Fatal(err)
				}
				if err := conn.WriteFrame(out); err != nil {
					log.Fatal(err)
				}
				wireBytes += int64(len(out))
				sent++
			}
			<-ticker.C
		}
	}

	time.Sleep(300 * time.Millisecond)
	elapsed := time.Since(start)

	mu.Lock()
	got := append([]time.Duration(nil), rtts...)
	mu.Unlock()
	var minRTT, maxRTT, sumRTT time.Duration
	for _, r := range got {
		if minRTT == 0 || r < minRTT {
			minRTT = r
		}
		if r > maxRTT {
			maxRTT = r
		}
		sumRTT += r
	}
	avgRTT := time.Duration(0)
	if len(got) > 0 {
		avgRTT = sumRTT / time.Duration(len(got))
	}

	if *receiptPath != "" {
		r := receipt.New(*name, "client", *runID, start, time.Now(), int64(sent), 0, wireBytes, priv)
		if err := receipt.Write(*receiptPath, r); err != nil {
			log.Printf("receipt: %v", err)
		}
	}

	loss := 0.0
	if sent > 0 {
		loss = 100 * float64(sent-len(got)) / float64(sent)
	}
	if *tunMode {
		fmt.Printf("client tag=%d handshake=%v tun=%s sent=%d wire=%dB elapsed=%s\n",
			tag, handshakeMode, tunDev.Name(), sent, wireBytes, elapsed.Round(time.Millisecond))
	} else {
		fmt.Printf("client tag=%d handshake=%v sent=%d replies=%d loss=%.2f%% payload=%dB cell=%dB frame=%dB elapsed=%s rate=%.0f pps\n",
			tag, handshakeMode, sent, len(got), loss, payloadSize, *cellSize, *frameSize, elapsed.Round(time.Millisecond), float64(sent)/elapsed.Seconds())
	}
	fmt.Printf("rtt min=%s avg=%s max=%s\n",
		minRTT.Round(time.Microsecond), avgRTT.Round(time.Microsecond), maxRTT.Round(time.Microsecond))
}
