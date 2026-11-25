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

	"dvpn-sim/internal/frame"
	"dvpn-sim/internal/onion"
	"dvpn-sim/internal/receipt"
)

type fwdState struct {
	prev   *net.UDPAddr
	outTag uint64
}

type relayState struct {
	mu  sync.Mutex
	in  map[uint64]*fwdState
	out map[uint64]uint64 // outTag -> inTag
}

func newRelayState() *relayState {
	return &relayState{
		in:  map[uint64]*fwdState{},
		out: map[uint64]uint64{},
	}
}

func (s *relayState) forward(inTag uint64, prev *net.UDPAddr, isExit bool) *fwdState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.in[inTag]; st != nil {
		st.prev = prev
		return st
	}
	st := &fwdState{prev: prev}
	if !isExit {
		for {
			t := randTag()
			if _, exists := s.out[t]; !exists {
				st.outTag = t
				s.out[t] = inTag
				break
			}
		}
	}
	s.in[inTag] = st
	return st
}

func (s *relayState) replyPeer(tag uint64, isExit bool) (*net.UDPAddr, uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if isExit {
		st := s.in[tag]
		if st == nil {
			return nil, 0, false
		}
		return st.prev, tag, true
	}
	inTag, ok := s.out[tag]
	if !ok {
		return nil, 0, false
	}
	st := s.in[inTag]
	if st == nil {
		return nil, 0, false
	}
	return st.prev, inTag, true
}

func randTag() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return binary.BigEndian.Uint64(b[:])
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
	isExit := dest != nil

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	start := time.Now()

	state := newRelayState()
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
		inner, typ, tag, err := frame.Decode(buf[:n])
		if err != nil {
			log.Printf("bad frame: %v", err)
			continue
		}

		if typ == frame.TypeReply {
			replyPackets.Add(1)
			replyIn.Add(uint64(n))
			peer, outTag, ok := state.replyPeer(tag, isExit)
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
		st := state.forward(tag, remote, isExit)

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
				if _, err := conn.WriteToUDP(out, st.prev); err != nil {
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
		out, err := frame.Encode(inner2, *frameSize, frame.TypeForward, st.outTag)
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
