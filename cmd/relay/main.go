package main

import (
	"crypto/ed25519"
	"crypto/rand"
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

	"dvpn-sim/internal/frame"
	"dvpn-sim/internal/onion"
	"dvpn-sim/internal/receipt"
)

type peerTable struct {
	mu sync.Mutex
	m  map[uint64]*net.UDPAddr
}

func (p *peerTable) set(cid uint64, addr *net.UDPAddr) {
	p.mu.Lock()
	p.m[cid] = addr
	p.mu.Unlock()
}

func (p *peerTable) get(cid uint64) *net.UDPAddr {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.m[cid]
}

func main() {
	id := flag.String("id", "", "this relay's node id")
	role := flag.String("role", "entry", "entry|middle|exit")
	name := flag.String("name", "", "receipt name (default: id)")
	runID := flag.String("run-id", "test", "run id for receipts")
	receiptPath := flag.String("receipt", "", "write a signed receipt JSON here on exit")
	keyHex := flag.String("key", "", "32-byte AES key, hex")
	listen := flag.String("listen", "127.0.0.1:17001", "UDP listen address")
	nextID := flag.String("next-id", "", "expected next hop id (empty for exit)")
	nextAddr := flag.String("next-addr", "", "next hop UDP address")
	destAddr := flag.String("dest", "", "destination UDP address (exit only)")
	frameSize := flag.Int("frame", 1024, "fixed wire frame size")
	flag.Parse()

	if *id == "" || *keyHex == "" {
		log.Fatal("-id and -key are required")
	}
	key, err := hex.DecodeString(*keyHex)
	if err != nil || len(key) != 32 {
		log.Fatal("-key must be 32 bytes hex")
	}
	if *name == "" {
		*name = *id
	}

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

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	start := time.Now()

	peers := &peerTable{m: map[uint64]*net.UDPAddr{}}
	var packets, bytesIn, bytesOut atomic.Uint64
	var replyPackets, replyIn, replyOut atomic.Uint64

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		if *receiptPath != "" {
			r := receipt.New(*name, *role, *runID, start, time.Now(),
				int64(packets.Load()), int64(bytesIn.Load()), int64(bytesOut.Load()), priv)
			if err := receipt.Write(*receiptPath, r); err != nil {
				log.Printf("receipt: %v", err)
			}
		}
		fmt.Printf("relay %s packets=%d in=%d out=%d replies=%d reply_in=%d reply_out=%d\n",
			*id, packets.Load(), bytesIn.Load(), bytesOut.Load(),
			replyPackets.Load(), replyIn.Load(), replyOut.Load())
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
		inner, typ, cid, err := frame.Decode(buf[:n])
		if err != nil {
			log.Printf("bad frame: %v", err)
			continue
		}
		if typ == frame.TypeReply {
			replyPackets.Add(1)
			replyIn.Add(uint64(n))
			peer := peers.get(cid)
			if peer == nil {
				log.Printf("reply for unknown circuit %d", cid)
				continue
			}
			out, err := frame.Encode(inner, *frameSize, frame.TypeReply, cid)
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
		// Only forward frames update the reverse path table.
		peers.set(cid, remote)

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
			if peer := peers.get(cid); peer != nil {
				out, err := frame.Encode(inner2, *frameSize, frame.TypeReply, cid)
				if err == nil {
					if _, err := conn.WriteToUDP(out, peer); err != nil {
						log.Printf("write reply: %v", err)
					} else {
						replyOut.Add(uint64(len(out)))
					}
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
		out, err := frame.Encode(inner2, *frameSize, frame.TypeForward, cid)
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
