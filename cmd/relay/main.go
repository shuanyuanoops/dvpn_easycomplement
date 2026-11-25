package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"dvpn-sim/internal/circuit"
	"dvpn-sim/internal/frame"
	"dvpn-sim/internal/handshake"
	"dvpn-sim/internal/onion"
	"dvpn-sim/internal/receipt"
)

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
	keyHex := flag.String("key", "", "optional fixed 32-byte AES key, hex (legacy)")
	listen := flag.String("listen", "127.0.0.1:17001", "UDP listen address")
	nextID := flag.String("next-id", "", "expected next hop id (empty for exit)")
	nextAddr := flag.String("next-addr", "", "next hop UDP address")
	destAddr := flag.String("dest", "", "destination UDP address (exit only)")
	frameSize := flag.Int("frame", 1024, "fixed wire frame size")
	tagTTL := flag.Duration("tag-ttl", 5*time.Minute, "idle timeout for circuit tags")
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

	var next *net.UDPAddr
	if *nextAddr != "" {
		next, err = net.ResolveUDPAddr("udp", *nextAddr)
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
	isExit := dest != nil

	_, receiptPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	start := time.Now()

	state := circuit.NewState()
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
	var packets, bytesIn, bytesOut atomic.Uint64
	var replyPackets, replyIn, replyOut atomic.Uint64
	var hsPackets atomic.Uint64

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
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
		inner, typ, tag, err := frame.Decode(buf[:n])
		if err != nil {
			log.Printf("bad frame: %v", err)
			continue
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
			keys.set(tag, key)
			if isExit {
				continue
			}
			if next == nil {
				log.Printf("handshake with no next")
				continue
			}
			out, err := frame.Encode(rest, *frameSize, frame.TypeHandshake, st.OutTag)
			if err != nil {
				log.Printf("handshake encode: %v", err)
				continue
			}
			if _, err := conn.WriteToUDP(out, next); err != nil {
				log.Printf("handshake forward: %v", err)
			}
			continue
		}

		if typ == frame.TypeReply {
			replyPackets.Add(1)
			replyIn.Add(uint64(n))
			peer, outTag, ok := state.ReplyPeer(tag, isExit)
			if !ok {
				log.Printf("reply for unknown tag %d", tag)
				continue
			}
			out, err := frame.Encode(inner, *frameSize, frame.TypeReply, outTag)
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
			if dest == nil {
				log.Printf("no -dest configured, dropping payload")
				continue
			}
			if _, err := conn.WriteToUDP(inner2, dest); err != nil {
				log.Printf("write dest: %v", err)
			} else {
				bytesOut.Add(uint64(len(inner2)))
			}
			out, err := frame.Encode(inner2, *frameSize, frame.TypeReply, tag)
			if err == nil {
				if _, err := conn.WriteToUDP(out, st.Prev); err != nil {
					log.Printf("write reply: %v", err)
				} else {
					replyOut.Add(uint64(len(out)))
				}
			}
			continue
		}

		if next == nil {
			log.Printf("no -next-addr configured")
			continue
		}
		if *nextID != "" && string(nextHop) != *nextID {
			log.Printf("next hop mismatch: got %s want %s", nextHop, *nextID)
			continue
		}
		out, err := frame.Encode(inner2, *frameSize, frame.TypeForward, st.OutTag)
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
